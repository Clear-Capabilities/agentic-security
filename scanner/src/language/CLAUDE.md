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
- **Pragma** (`pragma.js`): comment-aware, line-scoped, exact rule-id match, logged. A line-less finding cannot be suppressed.

## Module map

| Group | Files |
|---|---|
| Shared | `discovery.js` (sources, manifests, explicit exports, exclusions, import graph, invalidation digests), `contracts.js`, `assurance.js` (scan-health inputs, conditions, limitations), `engine-pass.js` (language supply chain wired into the engine), `resolved-pass.js` (plan / Stack export / Nix closure / opt-in evaluation reachable from the CLI), `context.js` (project context for partial scans, fix previews and dependency upgrades, model prompt extras), `state-artifacts.js`, `pragma.js`, `secrets.js`, `bom.js`, `bom-validate.js`, `aibom.js`, `compliance-map.js`, `bridges.js`, `witness.js`, `fix-lifecycle.js` (the one fix lifecycle: path, syntax, rescan, compile, backup, history, undo) |
| Haskell | `haskell-parser.js`, `haskell-grammar.js`, `haskell-adapter.js`, `haskell-ir.js`, `haskell-models.js` (the single registry of sources, sinks, sanitizers; `dataflow/catalog-haskell.js` is generated from it), `haskell-guards.js`, `haskell-security-rules.js`, `haskell-web.js`, `haskell-findings.js`, `haskell-syntax.js`, `haskell-sweep.js`, `haskell-disclosure.js`, `haskell-llm.js`, `haskell-manifests.js`, `haskell-resolved-graph.js`, `haskell-sca.js`, `cvss.js` (CVSS v3.x base-score calculator and advisory-severity selection, shared by the Haskell and Nix matchers; v4 is not scored and says so), `haskell-advisory-feed.js` (the opt-in live Hackage feed: OSV fetch, per-package coverage, operator-only snapshot), `haskell-supply.js`, `haskell-fix.js` |
| Nix | `nix-parser.js`, `nix-grammar.js`, `nix-ir.js`, `nix-adapter.js`, `nixos-module-resolver.js`, `nixos-option-catalog.js`, `nixos-hardening.js`, `nix-build-trust.js`, `nix-secrets.js`, `nix-script-taint.js`, `nix-privacy.js`, `nix-agents.js`, `nix-inventory.js`, `nix-closure.js`, `nix-sca.js`, `nix-eval-isolation.js`, `nix-fix.js` |
| Measurement | `accuracy.js` (family-scoped scoring, per-layer), `support-registry.js` (status rules, promotion refusals, frozen-hash demotion) |

Related, outside this directory: `dataflow/catalog-haskell.js`, `lineage/haskell-view.js`, `lineage/nix-view.js`,
`ir/` Haskell/Nix adapters, `report/` format handling, `egress/redact.js`, `llm-validator/`, `discovery/` (hunt partitions Nix).

## Tests and benches

| Scope | Command | Notes |
|---|---|---|
| Haskell | `npm run test:haskell` | parser, IR, taint, web/auth, SCA, resolved graph, remediation |
| Nix | `npm run test:nix` | parser/IR, module resolution, hardening, build trust, secrets, closure, SCA, eval isolation, fixes |
| Language-wide | `npm run test:language` | corpus integrity, accuracy regression, end-to-end CLI matrix, package/CI, BOM/AI-BOM, privacy, secrets, governance, assurance, scan modes |
| Stress | `npm run test:language-stress` | offline scale and a peak-memory ceiling; excluded from `npm test` (it must own the machine) |
| Needs a compiler | `npm run test:language-tools` | HS-006.AC01 and the support gate; excluded from `npm test`; **fails** without `ghc` |
| Support registry | `npm run bench:language-support:check` | recomputes the registry from the STORED measurement; fails on any difference |

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
