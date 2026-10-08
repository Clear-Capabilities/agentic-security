# scanner/src/language/

Haskell and Nix/NixOS support: parsers, IRs, analyzers, fixers, support registry. **Read this before adding a rule, a model entry
or a capability.** Product-facing guides: `docs/guides/haskell.md`, `docs/guides/nix-nixos.md`. Measured status:
`docs/language-support.md` (generated).

## Invariants (the ones you will get wrong without reading)

- **Static by default.** A default scan never runs GHC, Cabal, Stack, `nix`, `Setup.hs`, Template Haskell or a build. Compile
  checks (`haskell-fix.js` `compileGate`) and evaluation (`nix-eval-isolation.js`) are opt-in, and a tool that is absent is a
  stated `not-run` / `unsupported`, never a pass. A required criterion that needs a tool **fails** (and the support registry
  marks the capability `blocked`); it never skips.
- **Never derive an answer from ground truth.** The engine must not read the corpus under `test/language/corpora/`, fixture
  names, comments or label metadata (a test enforces the corpus half). Detection keys on code semantics; `bench/mutation/`
  and the metamorphic pairs in `bench/language-support/` are the anti-overfitting check.
- **Every limit is disclosed.** An unresolved construct, a conditional Nix option, a stale plan, a missing advisory feed, a
  malformed export, a size-capped file, a disabled analyzer: each becomes a `scanHealth` condition or a limitation
  (`assurance.js`). Findings are never dropped because a condition appeared, and an absent feed is "not assessed", never clean.
- **Findings schema.** Optional contract fields (`language`, `capability`, `evidenceKind`, `scope`, `uncertainty`,
  `originalLocation`) in `contracts.js`; the legacy required fields are unchanged. A producer must be registered
  (`producer-registry.js`) or its results are discarded and reported.
- **Locations index the ORIGINAL file** (1-based lines, 0-based UTF-16 columns, UTF-8 bytes). Preprocessing (CPP, literate,
  hsc) overwrites with same-length spaces.
- **State safety.** Persisted language artifacts go through `posture/state-dir.js` (`statePath`, `safeWriteState`); a symlinked
  state dir or file is refused; fix backups are encrypted when encryption is configured and are `confidential`. A fix target
  outside the project root is refused (`fix-lifecycle.js` `isRootRelativePath`).
- **Secrets never leave redacted.** `secrets.js` `redactLanguageSecrets` joins split literals before masking; egress and model
  prompts use it. Credential values are never written to any output or state file.
- **The advisory feed is opt-in and records coverage.** `haskell-advisory-feed.js` touches the network only when
  `AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1` and never under `AGENTIC_SECURITY_OFFLINE`. Its snapshot lists the packages it actually
  queried (`covered`); a package it did not cover is `feed-incomplete` and a stale one `feed-stale`, in BOTH matchers
  (`evaluateComponents` and `nix-sca.js`). Any new consumer of an `AdvisoryDb` must check `db.coverage(name)` before saying "no advisory".
  The snapshot lives in the operator configuration directory, never the project (`trusted-inputs.js`).
- **Auth guards must stop the handler.** In `haskell-web.js` a Scotty `status 40x` only sets the code, so both the named-guard path (`guardSummary`) and the inline path (`handlerFacts`) need a halting call (`finish`, `raise`, `raiseStatus`, `redirect`; `finish` is an IR identifier with no line of its own). WAI, Servant and Yesod inline guards order the credential READ against the first sensitive call, because a tail-position rejection reports the enclosing line (a disclosed gap, pinned in `test/haskell/haskell-web-guards.test.js`). A WAI `responseLBS` rejection counts only when handed back (`respond`/`return`).
- **Severity is the advisory's own** (`cvss.js`): CVSS v3.x base score, else a named `database_specific.severity`, else `medium` with the basis stated. Never guess from an unparseable or v4 vector.
- **Option fixes work on the effective configuration, across files.** `nix-fix.js` edits EVERY contributing definition of an option
  (all winners at the winning priority, plus conditional branches holding the weak literal), never one line: editing one of two
  equal-priority winners turns a finding into a module-system conflict that a rescan alone reports as "fixed". Verification is
  the `effective` gate (`makeEffectiveCheck`: resolve the option again over the patched tree). A plan may carry `edits` (several
  files); `runFixLifecycle` applies them through `writeManyWithBackup` (checks everything and backs up everything before the
  first write, rolls back on a failed write) and records one history entry per file sharing `languageGroupId`; `undoFix` and
  `posture/fix-history.js` `undoLast`/`revertEntryById` restore a group as a unit. A winner outside the root or not a single
  literal is refused with an `override` suggestion (`overrideSuggestion`), never an automatic edit. Any new consumer of a fix
  plan (LSP, MCP, CLI) must honour `plan.edits`: `apply_fix` writes one file, so a multi-file fix is not offered there.
- **Boundaries are narrowed only by sound, closed rules.** `haskell-cpp.js` decides a CPP conditional only from the file, a project-stated
  compiler (`with-compiler` pin; `tested-with` only when every item is an exact version and all agree, recorded as an assumption) or the hull
  of cabal `build-depends` bounds; an unknown macro is undecided, never 0, and an undecided conditional keeps every branch. `haskell-boundaries.js`
  accepts a TH declaration splice only when the generator is IMPORTED from its upstream module (not shadowed/hidden) and every token is a name
  quote, literal, documented setting or restricted option update; a quasi-quote only when it is a raw-string or non-interpolating quoter. The
  accepted kinds (`th-safe-splice`, `quasiquote-inert`) are disclosed, never in the adapter's opaque set, and `preprocessForSyntax` feeds the same
  decisions to the semantic IR. Widening any allowlist needs a both-directions test in `test/haskell/haskell-boundaries.test.js`.
- **The Nix feed is the same contract over a different source.** `nix-advisory-feed.js` uses the NVD CVE API 2.0 keyed by CPE
  `vendor:product` (OSV has no nixpkgs ecosystem), behind `AGENTIC_SECURITY_NIX_ADVISORIES_LIVE=1`. Coverage is per CPE identity
  (`NixAdvisoryData.cpeCoverage`), and `nix-sca.js` reports an uncovered identity, or a component with no CPE, as `unknown` with
  `feedCoverage: 'incomplete'`, never `not-affected`. A snapshot with no `covered` table (pinned, hand-written) is matched exactly as
  before. The prefetch (`prefetchNixAdvisoryFeed`, `resolved-pass.js`) asks only for identities `closureIdentities` says the matcher
  will use; metadata comes only from the operator (`AGENTIC_SECURITY_NIX_META`). NVD is rate limited (5/30 s keyless): never raise
  the request caps or lower the spacing in `nix-advisory-feed.js` without re-reading the NVD limits.
- **Pragma** (`pragma.js`): comment-aware, line-scoped, exact rule-id match, logged. A line-less finding cannot be suppressed.

## Module map

| Group | Files |
|---|---|
| Shared | `discovery.js` (sources, manifests, explicit exports, exclusions, import graph, invalidation digests), `contracts.js`, `assurance.js` (scan-health inputs, conditions, limitations), `engine-pass.js` (language supply chain wired into the engine), `resolved-pass.js` (plan / Stack export / Nix closure / opt-in evaluation reachable from the CLI), `context.js` (project context for partial scans, fix previews and dependency upgrades, model prompt extras), `state-artifacts.js`, `pragma.js`, `secrets.js`, `bom.js`, `bom-validate.js`, `aibom.js`, `compliance-map.js`, `bridges.js`, `witness.js`, `fix-lifecycle.js` (the one fix lifecycle: path, syntax, rescan, compile, backup, history, undo) |
| Haskell | `haskell-parser.js`, `haskell-grammar.js`, `haskell-adapter.js`, `haskell-ir.js`, `haskell-models.js` (the single registry of sources, sinks, sanitizers; `dataflow/catalog-haskell.js` is generated from it), `haskell-guards.js`, `haskell-security-rules.js`, `haskell-web.js`, `haskell-findings.js`, `haskell-syntax.js`, `haskell-sweep.js`, `haskell-disclosure.js`, `haskell-llm.js`, `haskell-manifests.js`, `haskell-resolved-graph.js`, `haskell-sca.js`, `cvss.js` (CVSS v3.x base-score calculator and advisory-severity selection, shared by the Haskell and Nix matchers; v4 is not scored and says so), `haskell-advisory-feed.js` (the opt-in live Hackage feed: OSV fetch, per-package coverage, operator-only snapshot), `haskell-supply.js`, `haskell-fix.js` |
| Haskell | `haskell-parser.js`, `haskell-cpp.js` (three-valued CPP conditional evaluation + project context from cabal), `haskell-boundaries.js` (closed set of safe TH declaration splices and inert quasi-quotes), `haskell-grammar.js`, `haskell-adapter.js`, `haskell-ir.js`, `haskell-models.js` (the single registry of sources, sinks, sanitizers; `dataflow/catalog-haskell.js` is generated from it), `haskell-guards.js`, `haskell-security-rules.js`, `haskell-web.js`, `haskell-findings.js`, `haskell-syntax.js`, `haskell-sweep.js`, `haskell-disclosure.js`, `haskell-llm.js`, `haskell-manifests.js`, `haskell-resolved-graph.js`, `haskell-sca.js`, `haskell-advisory-feed.js` (the opt-in live Hackage feed: OSV fetch, per-package coverage, operator-only snapshot), `haskell-supply.js`, `haskell-fix.js` |
| Nix | `nix-parser.js`, `nix-grammar.js`, `nix-ir.js`, `nix-adapter.js`, `nixos-module-resolver.js`, `nixos-option-catalog.js`, `nixos-hardening.js`, `nix-build-trust.js`, `nix-secrets.js`, `nix-script-taint.js`, `nix-privacy.js`, `nix-agents.js`, `nix-inventory.js`, `nix-closure.js`, `nix-sca.js`, `nix-eval-isolation.js`, `nix-fix.js` |
| Haskell | `haskell-parser.js`, `haskell-grammar.js`, `haskell-adapter.js`, `haskell-ir.js`, `haskell-models.js` (the single registry of sources, sinks, sanitizers; `dataflow/catalog-haskell.js` is generated from it), `haskell-guards.js`, `haskell-security-rules.js`, `haskell-web.js`, `haskell-findings.js`, `haskell-syntax.js`, `haskell-sweep.js`, `haskell-disclosure.js`, `haskell-llm.js`, `haskell-manifests.js`, `haskell-resolved-graph.js`, `haskell-sca.js`, `haskell-advisory-feed.js` (the opt-in live Hackage feed: OSV fetch, per-package coverage, operator-only snapshot), `haskell-supply.js`, `haskell-fix.js` |
| Nix | `nix-parser.js`, `nix-grammar.js`, `nix-ir.js`, `nix-adapter.js`, `nixos-module-resolver.js`, `nixos-eval-forms.js`, `nixos-option-catalog.js`, `nixos-hardening.js`, `nix-build-trust.js`, `nix-secrets.js`, `nix-script-taint.js`, `nix-privacy.js`, `nix-agents.js`, `nix-inventory.js`, `nix-closure.js`, `nix-sca.js`, `nix-eval-isolation.js`, `nix-fix.js` |
| Haskell | `haskell-parser.js`, `haskell-grammar.js`, `haskell-adapter.js`, `haskell-ir.js`, `haskell-models.js` (the single registry of sources, sinks, sanitizers; `dataflow/catalog-haskell.js` is generated from it), `haskell-guards.js`, `haskell-security-rules.js`, `haskell-web.js`, `haskell-findings.js`, `haskell-syntax.js`, `haskell-sweep.js`, `haskell-disclosure.js`, `haskell-llm.js`, `haskell-manifests.js`, `haskell-resolved-graph.js`, `haskell-sca.js`, `haskell-advisory-feed.js` (the opt-in live Hackage feed: OSV fetch, per-package coverage, operator-only snapshot), `haskell-supply.js`, `haskell-fix.js` |
| Nix | `nix-parser.js`, `nix-grammar.js`, `nix-ir.js`, `nix-adapter.js`, `nixos-module-resolver.js`, `nixos-option-catalog.js`, `nixos-hardening.js`, `nix-build-trust.js`, `nix-secrets.js`, `nix-script-taint.js`, `nix-privacy.js`, `nix-agents.js`, `nix-inventory.js`, `nix-closure.js`, `nix-sca.js`, `nix-advisory-feed.js`, `nix-eval-isolation.js`, `nix-fix.js` |
| Measurement | `accuracy.js` (family-scoped scoring, per-layer), `support-registry.js` (status rules, promotion refusals, frozen-hash demotion) |

Related, outside this directory: `dataflow/catalog-haskell.js`, `lineage/haskell-view.js`, `lineage/nix-view.js`,
`ir/` Haskell/Nix adapters, `report/` format handling, `egress/redact.js`, `llm-validator/`, `discovery/` (hunt partitions Nix).

## NixOS option evaluator (soundness rules)

`nixos-module-resolver.js` `evalExpr` is a soundness-first subset; `nixos-eval-forms.js` holds its value classes and the
**allow-list** of library functions (there is no deny-list to forget an entry in). Rules to keep when extending it:

- **Any unknown part makes the whole value unknown.** Never default, never pick a branch you cannot decide.
- **Scope is a correctness issue.** Lexical bindings (let, lambda) beat every `with`; innermost `with` beats outer; the module's
  own `let`s are IR bindings (`ir.bindings`, `scope: 'let'`) and are used only when unique in the file, not also a function
  parameter, not in a `rec` set, and when their `letSpan` encloses `env.pos` (the absolute span of the text being evaluated).
  `evalSpan` on a definition (set by `nix-ir.js` when a leaf sits under let/with/assert only) makes the resolver evaluate the
  whole wrapper. A priority/condition/merge combinator clears it, because those are the collector's job.
- **Final values must be plain data** (`sealed`/`isPlain`): a closure, partial application or namespace is `unknown`. A
  priority wrapper inside a value is unknown (priority is not recoverable); at the top of a definition the collector reads it.
- **Bounded**: `maxEvaluations`, `maxExprDepth`, `maxValueSize` are caps that surface as `truncated`, not as a guess.
- Assumption stated, not proven: `lib` is nixpkgs' `lib` whenever the module declares a `lib` parameter and the file does not rebind it.

## Tests and benches

| Scope | Command | Notes |
|---|---|---|
| Haskell | `npm run test:haskell` | parser, IR, taint, web/auth, SCA, resolved graph, remediation |
| Nix | `npm run test:nix` | parser/IR, module resolution, hardening, build trust, secrets, closure, SCA, eval isolation, fixes |
| Language-wide | `npm run test:language` | corpus integrity, accuracy regression, end-to-end CLI matrix, package/CI, BOM/AI-BOM, privacy, secrets, governance, assurance, scan modes |
| Stress | `npm run test:language-stress` | offline scale and a peak-memory ceiling; excluded from `npm test` (it must own the machine) |
| Needs a compiler | `npm run test:language-tools` | HS-006.AC01 and the support gate; excluded from `npm test`; **fails** without `ghc` |
| Support registry | `npm run bench:language-support:check` | recomputes the registry from the STORED measurement; fails on any difference |
| Live feed | `npm run bench:live-feed -- <fetch\|plan\|scan\|merge\|sample\|report>` | `bench/live-feed/`: the opt-in Hackage feed against real projects and real OSV. Needs the network and is NOT in `npm test` or any gate. `RESULTS.md` is a dated measurement; labels in it are model-assessed |

The support registry is measured **once per promotion** on a frozen holdout (`bench/language-support/promote.mjs`); never tune
against the holdout, and any further holdout run counts as repeated use. A change to the engine, the corpus or a label changes the
frozen hashes and demotes rows until a deliberate re-measure. `docs/language-support.*` are generated; do not edit by hand.

## Docs generated from here

`node scripts/render-language-docs.mjs` renders tables and counts from the registries (models, hardening, build-trust, secrets,
support, metrics) and from `docs/examples/language/captured.json`, which `node scripts/capture-language-examples.mjs` captures
from the BUILT bundle over `examples/`. Both have `--check` modes (`npm run docs:check-language`). Rebuild the bundle first:
the capture reads `dist/`.

## Adding a rule or a model entry

1. Haskell API: add it to `haskell-models.js` (module-qualified). The catalog and lineage registries follow, and **pinned counts in
   `test/lineage/{source,sink,transform}-registry.test.js` change deliberately** (update them and say why).
2. Nix rule: add it to the rule table of its analyzer (`nixos-hardening.js`, `nix-build-trust.js`, `nix-secrets.js`); the guide's
   table is generated, so re-render.
3. Add a minimal vulnerable / safe pair to the QA-001 templates (`test/language/corpora/templates.mjs`), regenerate the corpus, and
   record the revision in `provenance.json`. Do not hand-edit labels.
4. Run `test:haskell` / `test:nix` / `test:language`, `bench:mutation:check`, `bench:layer-recall:check` and
   `bench:language-support:check`; re-promote deliberately if a measured number legitimately changes.
