# Haskell and Nix/NixOS analysis: contract

**Maturity:** Preview

This page freezes two surfaces of the Haskell and Nix/NixOS analysis: the language pipeline contract in `scanner/src/language/contracts.js` (contract version `1`, the `LANGUAGE_CONTRACT_VERSION` constant, carried as `schemaVersion` on the language health record), and the shape of the generated support registry `docs/language-support.json` (schema `agentic-security/language-support@1`, version `language-support/1`). The test `scanner/test/contracts/language-depth.contract.test.js` holds the code to every table on this page in both directions: a field or value the code has that this page does not list fails, and so does one this page lists that the code lacks. It also runs each rule below on small inline inputs, with no network and no compiler.

Freezing the contract does not promote the capability. The support registry is measured on a synthetic, template-generated corpus, and real-project accuracy is not part of that measurement (see the last section).

## Finding and component metadata

The language fields are additive and optional. The legacy required finding fields (`id`, `severity`, `file`, `line`, `vuln`, `cwe`, `description`, `remediation`, `parser`, `family`) stay required exactly as before, so an output written before this contract still validates. `validateLanguageFinding` checks a language field only when it is present, and rejects a value outside its vocabulary. `withLanguageMetadata` fills these fields from supplied metadata without overwriting a value the detector already set; `language` falls back to the file extension.

**Finding metadata**

| Field | Meaning |
|---|---|
| `language` | One of the languages below. |
| `capability` | One of the capabilities below. |
| `evidenceKind` | One of the evidence kinds below. |
| `scope` | An object; each of its keys below is a string or `null`. |
| `uncertainty` | An array of entries, each with a `kind` from the uncertainty kinds below. |
| `originalLocation` | Where the finding sits in the original file, before any preprocessing. |
| `producer` | The id of the registered producer that emitted the finding; an unregistered id fails validation. |

**Scope**

| Field | Meaning |
|---|---|
| `target` | The build target (for example a Cabal component or a NixOS host). |
| `configuration` | The configuration the result holds for. |
| `component` | The component the result belongs to. |

**Original location**

| Field | Meaning |
|---|---|
| `line` | Required, an integer from 1. |
| `column` | Optional, an integer from 0 (0-based UTF-16). |
| `file` | Optional, a string. |

A component (an inventory or bill-of-materials entry) is validated by `validateLanguageComponent`: `name` is required and non-empty, `version` is a string or `null` when present, and the same language fields above are checked when present.

**Languages**

| Value | Meaning |
|---|---|
| `haskell` | Haskell sources (`.hs`, `.lhs`, `.hs-boot`, `.lhs-boot`, `.hsig`, `.hsc`). |
| `nix` | Nix expressions (`.nix`). |

**Capabilities**

| Value | Meaning |
|---|---|
| `parse` | Parsing and the parse ledger. |
| `sast` | Rule-based detection. |
| `taint` | Source-to-sink data flow. |
| `sca` | Dependency and build-trust analysis. |
| `config` | Configuration analysis. |
| `iac` | Infrastructure-as-code analysis. |
| `privacy` | Privacy data flow. |
| `route-inventory` | Route and entry-point inventory. |

**Evidence kinds**

| Value | Meaning |
|---|---|
| `source` | Read from source code. |
| `manifest` | Read from a package manifest. |
| `lock` | Read from a lock file or a resolved export. |
| `config` | Read from declared configuration. |
| `generated-script` | Read from a script a derivation generates. |
| `runtime` | Observed runtime state. |

For Nix, a generated script, the static configuration that declares it and observed runtime state are different claims and never share a kind.

**Uncertainty kinds**

| Value | Meaning |
|---|---|
| `unresolved-import` | An import that could not be resolved. |
| `unresolved-branch` | A branch the analyzer could not decide. |
| `generated-source` | Generated code. |
| `preprocessed` | Code changed by a preprocessor before analysis. |
| `partial-parse` | Only part of the file parsed. |
| `unresolved-target` | A call whose target is not known; taint is widened across it, never dropped. |
| `foreign-boundary` | A call into code that is not analysed (a foreign function). |
| `untested-model` | The library version is not one the model was written against; results are best effort. |

## Producer registry

Every language analyzer is registered with `registerLanguageProducer`, which also mirrors it into the shared pipeline producer registry. Registration refuses an unknown language, capability or evidence kind, a missing id and a duplicate id, by throwing.

**Producer definition**

| Field | Meaning |
|---|---|
| `id` | Unique; `language:<name>` by convention. |
| `language` | One of the languages above. |
| `capability` | One of the capabilities above. |
| `evidenceKinds` | The evidence kinds it may emit (default `["source"]`). |
| `version` | The producer version (default `"1"`). |

Rules:

- **Unregistered producers are discarded and reported.** When `runLanguageAnalysis` is handed an adapter whose id is not registered, the adapter is not called: none of its results reach the findings, the file is recorded `unresolved` for that analyzer (never clean), and an `unregistered-producer` outcome is recorded, which `languageHealth` turns into a condition saying the results were discarded.
- **Findings from a registered producer carry its identity.** Each finding gets `language`, the producer's `capability` and `producer`, unless the detector set them.

## Coverage outcomes

`runLanguageAnalysis({files, adapters, timeoutMs})` drives the registered adapters over a file set (relative path to text). For each discovered language source and each adapter of its language it records exactly one file status. Nothing it does runs scanned code: adapters are functions over file text.

**File statuses**

| Value | Meaning |
|---|---|
| `analyzed` | Read, with no unresolved branch. |
| `excluded` | Reserved in the vocabulary; see the note below. |
| `unresolved` | Read with an unresolved branch, or the adapter is not a registered producer. |
| `failed` | The adapter threw. |
| `timed_out` | The adapter ran past `timeoutMs`. |
| `missing_grammar` | The adapter's grammar is missing or does not match its pinned checksum; the file is not parsed and nothing throws. |

**Outcome kinds**

| Value | Meaning |
|---|---|
| `missing-grammar` | The grammar was unavailable for this file and analyzer. |
| `adapter-exception` | The adapter threw; `detail` carries the message. |
| `unresolved-branch` | A branch the adapter left unresolved, with `line` and `detail`; reported on top of the file status. |
| `timeout` | The adapter timed out. |
| `unregistered-producer` | The adapter is not a registered producer; its results were discarded. |
| `excluded-path` | The file is under a build-output or store directory (`dist-newstyle`, `.stack-work`, `.cabal-sandbox`, `.direnv`, `nix/store`). |
| `unsupported-language` | A language source no supplied adapter handles. |

**Run result**

| Field | Meaning |
|---|---|
| `findings` | Findings from registered producers only, with language metadata added. |
| `ledger` | The per-file, per-analyzer record below. |
| `outcomes` | One record per outcome above, with `kind`, `file`, `language` and, where it applies, `analyzer`, `line` and `detail`. |

**Ledger**

| Field | Meaning |
|---|---|
| `byFile` | File to analyzer id to file status. |
| `byAnalyzer` | Analyzer id to the counts below. |
| `discoveredFiles` | Language sources that were analyzer inputs. |
| `excludedFiles` | Language sources skipped as excluded paths. |

**Analyzer counts**

| Field | Meaning |
|---|---|
| `language` | The analyzer's language. |
| `discovered` | Files it was applied to. |
| `analyzed` | Files with status `analyzed`. |
| `excluded` | Files with status `excluded`. |
| `unresolved` | Files with status `unresolved`. |
| `failed` | Files with status `failed`. |
| `timedOut` | Files with status `timed_out`. |
| `missingGrammar` | Files with status `missing_grammar`. |

**Language health** (the `languageCoverage` input of scan health)

| Field | Meaning |
|---|---|
| `schemaVersion` | The contract version, `1`. |
| `totals` | The analyzer counts summed, with excluded paths added to `excluded`. |
| `byKind` | Outcome kind to count. |
| `conditions` | Sentences for missing grammars, adapter exceptions, timeouts, unresolved branches and discarded unregistered results. |

Rules:

- **Reconciliation.** `reconcileLanguageLedger(ledger, files)` fails when a real language source is not accounted for, when the ledger names a file that is not a real input, when a file is both discovered and excluded, when an analyzer's statuses do not sum to its `discovered` count or its per-file rows disagree with it, or when a status is outside the vocabulary.
- **Gaps are not clean.** A missing grammar, an exception, a timeout and an unregistered producer each leave the file in a non-`analyzed` status and add a condition; none of them is silent.
- **The `excluded` status is reserved, not emitted.** `runLanguageAnalysis` never assigns `excluded` to a file: an excluded path gets no per-file row, is listed in `excludedFiles` with an `excluded-path` outcome, and is added to `totals.excluded` by `languageHealth`. A per-analyzer `excluded` count from `runLanguageAnalysis` is therefore always 0.

## The support registry

`docs/language-support.json` is generated by `bench/language-support/promote.mjs` from a stored measurement and checked for freshness by `npm run bench:language-support:check`; it is never edited by hand.

**Registry envelope**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/language-support@1`. |
| `version` | `language-support/1`. |
| `generatedAt` | The date of the measurement. |
| `node` | The Node version the suites ran under. |
| `targets` | The numerical gates (precision, recall, F1, per-family F1, minimum holdout and privacy case counts). |
| `pairGate` | The metamorphic pair gate (`change`, `preserve`). |
| `languages` | One entry per language, below. |
| `tools` | What was present on the measuring host, below. |
| `generalization` | The unseen split the rows are reported beside, its role and dates, or `null`. |
| `limits` | Sentences stating what the measurement does not establish. |
| `verified` | The registry's re-check of its recorded corpus hashes against the corpus as it is now (`ok`, `stale`). |

**Language entry**

| Field | Meaning |
|---|---|
| `frozen` | The corpus hashes the rows were measured against. |
| `measuredOn` | Split, date, corpus version, hashes and totals of the measurement. |
| `rows` | One capability row per required capability. |
| `summary` | Required, supported and not-supported counts. |
| `generalizationGaps` | Unseen-split shortfalls per capability. |
| `metamorphic` | Pair-gate result, or `null`. |
| `unknownOutcomes` | Cases that came back with neither a finding nor a disclosure, or `null`. |
| `modelledVersions` | The package and framework versions the Haskell models were written against; `null` for Nix. |

**Capability row**

| Field | Meaning |
|---|---|
| `capability` | The capability name. |
| `status` | One of the row statuses below. |
| `reasons` | Why the row is not supported (empty when it is). |
| `evidence` | The metric kind and the measured values, or `null`. |
| `generalization` | Present on detection rows only: the unseen-split result (`not-measured`, `below-target` or `meets-targets`); it never changes the row status. |

**Row statuses**

| Value | Meaning |
|---|---|
| `supported` | Every criterion has passing evidence of the row's own metric kind on the frozen corpus. |
| `failed` | Measured and below target, or a backing suite failed or skipped. |
| `not-measured` | No evidence of the right kind; an absent denominator is never 100%. |
| `blocked` | A required tool or host is absent (or the compiler is not the recorded toolchain): the criterion could not run, which is never a pass and never a skip. |
| `unverified` | The promotion check refused the evaluated status. |

**Required capabilities: haskell**

| Capability | Metric kind that may promote it |
|---|---|
| `parser` | `parse-fixtures` |
| `sast` | `sast-holdout` |
| `taint` | `taint-holdout` |
| `privacy-lineage` | `privacy-holdout` |
| `auth` | `auth-detection` (blocked without `ghc`) |
| `sca` | `sca-fixtures` |
| `bom` | `test-suite` |
| `fix` | `fix-fixtures` |
| `integration` | `test-suite` |

**Required capabilities: nix**

| Capability | Metric kind that may promote it |
|---|---|
| `parser` | `parse-fixtures` |
| `config-sast` | `sast-holdout` |
| `config-taint` | `taint-holdout` |
| `privacy-lineage` | `privacy-holdout` |
| `sca` | `sca-fixtures` |
| `bom` | `test-suite` |
| `fix` | `fix-fixtures` |
| `integration` | `test-suite` |
| `nix-eval` | `test-suite` (blocked without `nix`) |
| `nixos-host` | `host-run` (blocked without a NixOS host) |

**Tools**

| Field | Meaning |
|---|---|
| `ghc` | Whether a compiler was present. |
| `ghcVersion` | Its version. |
| `ghcRecorded` | The recorded toolchain version. |
| `ghcMatchesRecorded` | Whether the two agree. |
| `cabal` | Whether `cabal` was present. |
| `stack` | Whether `stack` was present. |
| `nix` | Whether `nix` was present. |
| `nixos` | Whether the host was NixOS. |
| `platform` | The host platform. |
| `arch` | The host architecture. |

Rules:

- **Absent tool means blocked.** A capability listed with a tool above is `blocked` whenever that tool is absent on the measuring host, whatever its tests say.
- **Evidence of another kind never promotes.** A row may be `supported` only from evidence of its own metric kind; `installation`, `grammar-present`, `structural-only`, `documentation`, `model-assertion`, `taint-as-privacy` and `unknown` evidence can never promote a row.

## What this does not do

<!-- limits-verified: 2026-11-13 -->

- The support registry is measured on a synthetic, template-generated corpus (QA-001, `scanner/test/language/corpora/`): holdout cases vary nouns, fields and paths over the same shapes as the development cases. A `supported` row says nothing about accuracy on arbitrary real-world code, which the registry does not measure.
- The unseen split reported beside the rows is a development set (its failures were read and the engine was changed for them), so its column is a regression result, not a generalisation one.
- Where `nix`, a NixOS host, `stack` or the recorded `ghc` is absent on the measuring host, the legs that need it do not run; the rows that depend on them are `blocked` (in the committed registry, `nix-eval` and `nixos-host`), never reported as passing.
- A default scan executes nothing it analyses: no compiler, build tool, `nix` evaluation, `Setup.hs` or Template Haskell runs. The compile check and controlled evaluation are opt-in and an absent tool is stated as not run.
- `runLanguageAnalysis` does not check that a finding's `evidenceKind` is one its producer declared, that a detector-set `capability` matches the producer's, or that an adapter's `language` matches its registration; the validators check vocabularies, not these pairings.
- `scope` and `originalLocation` are not closed: the validator checks the keys listed above and accepts any other key without complaint.
- The `excluded` file status is in the vocabulary but is never assigned by `runLanguageAnalysis`; excluded paths are reported through `excludedFiles` and the `excluded-path` outcome instead.
- `languageHealth` reports counts and conditions; it carries no single complete or partial status of its own, and an excluded path or an unsupported-language file adds no condition.
- An `sca` row with no supply measurement at all is `failed` (with the reason "no manifest-resolution measurement"), not `not-measured` as the other rows are when their evidence is absent.
- The header of `support-registry.js` describes a `partial` row status that no code path assigns; it is not part of the vocabulary above.
- The row status set is not an exported constant: it is fixed by the code paths of `support-registry.js` and `registry-build.mjs`, and the contract test checks it against those files and the committed registry.
