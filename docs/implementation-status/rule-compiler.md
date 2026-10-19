# Implementation status: Self-Learning Finding-to-Rule Compiler (PRD 3)

## Status summary (2026-10-18)

* **Percent complete:** 7 of 8 P0 requirements fully evidenced; 1 partial. Requirement 8 (regression integration) is a working per-installation mechanism (fixtures, a shared false-positive corpus, `rules regress`) but a promoted rule is not added to this repository's own `bench/` corpora. Requirement 2 compiles source, sink, propagator, sanitizer, guard, framework constraint, exclusions and language; an AST pattern is not supported (the engine has no AST matcher to compile to).
* **Current phase:** G (completion): built, documented, released; ongoing work is hardening.
* **Completed requirements:** Eligibility, the rule IR with enforced structure, automatic corpus with seven mutators on both sides, the synthesis loop, the promotion gate, provenance, the lifecycle ledger, `rules synthesize|evaluate|promote|status|rollback|cost|regress`, signing on promotion with a truthful `live` status, and the killer scenario against a real spawned CLI and a real scan.
* **Current work:** None in flight.
* **Remaining requirements:** AST-pattern rules; adding a promoted rule to this repository's bench corpora; an MCP tool for synthesis; a real benchmark population behind the anti-cheating check (it is a pattern check on the synthesis material).
* **Failing tests:** None at the last run.
* **Blockers:** None structural.
* **Last verified command:** `node --test test/rule-compiler/*.test.js test/cli/rule-compiler-cli.test.js` (scanner/): 38 pass, 0 fail.

---

**Percent complete (updated):** all eight P0 requirements are implemented and tested; the follow-up list below closes the gaps this
page first disclosed. Original summary, kept for the record:

**Percent complete (original):** the deterministic promotion half (requirements #2, #5, #6, #7, #8 of the PRD) is done and
tested end to end, including the killer scenario. #1 (eligibility) is done. #3 (automatic corpus creation) is done
for the positive/patched/nearby-clean/protected-variant shapes the PRD names. #4 (mutation engine) is implemented
with three of the seven listed mutator kinds (variable rename, wrapper, indirection); the other four (equivalent
APIs, reordered statements, alternate sanitizers, framework variants) are not built. There is no automatic
PATTERN-PROPOSAL step — the candidate regex always comes from the caller.

**Current phase:** F (documentation) done; G (completion) in progress.

**Branch:** `feature/proof-fabric` (shared branch with PRD 1; not yet merged).

**Completed requirements (with evidence):**
- Rule IR compiling into the EXISTING `posture/custom-rules.js` matcher, not a parallel engine —
  `scanner/src/posture/rule-compiler/ir.js`, `test/rule-compiler/core.test.js`.
- Eligibility check reusing the existing proof-tier/evidence-state vocabularies — `eligibility.js`.
- Bounded, deterministic, semantics-preserving mutation generator (variable-rename, wrap-in-function,
  insert-indirection) — `mutation.js`.
- Automatic corpus creation (positive: original + siblings; negative: patched + its siblings, nearby-clean,
  protected variants) and scoring through the real runtime matcher — `corpus.js`.
- Promotion gate (precision ≥95%, recall ≥80%, zero protected-negative failures, configurable) with an
  independent (not reused — see below) anti-cheating leakage check — `promotion.js`.
- DRAFT→CANDIDATE→VALIDATED→PROMOTED→DEPRECATED/ROLLED_BACK lifecycle, append-only and hash-chained; no edge
  skips a rung; tamper-evident — `lifecycle.js`.
- Persistence: per-rule ledger/IR/evaluation under `.agentic-security/rule-compiler/`, the promoted rule published
  to the EXISTING `.agentic-security/rules/` directory (so `loadCustomRules`/`agentic-security rule test` pick it
  up with no code change), and regression fixtures written in the existing `vulnerable`/`clean` convention —
  `store.js`, registered in `artifact-registry.js`.
- CLI: `rules synthesize|evaluate|promote|status|rollback`, folded into the EXISTING `cmdRules` dispatcher
  (distinct from the pre-existing `rules validate`/`rules lock` — see the collision note below) —
  `cli.js`, `bin/agentic-security.js`, `test/cli/rule-compiler-cli.test.js` (3 tests against the real spawned CLI,
  including the killer E2E scenario).
- Killer E2E scenario, with a GROUNDED real miss (verified by a real `scan` in this session: the deterministic
  engine does not recognize `db.rawQuery(...)` string concatenation as a SQL sink): synthesize → evaluate →
  promote → the original finding's file is caught → an UNSEEN sibling (different file, renamed identifiers, extra
  indirection, never in the corpus) is caught too, with no model call possible in the test environment → rollback
  removes it again. `test/cli/rule-compiler-cli.test.js`.

**A real naming collision found and fixed.** The PRD's own CLI example (`agentic-security rules ...`) collided
with a pre-existing, shipped command: `rules validate` (lint `.agentic-security/rules.yml` overrides) and
`rules lock` (write a rule-pack lockfile). A first pass added a second, duplicate `case 'rules':` switch arm —
which JavaScript resolves to the FIRST matching case, so the original `rules validate`/`rules lock` would have
become permanently unreachable, silently, the moment this shipped. Fixed by folding the new subcommands into the
existing `cmdRules` function instead of adding a competing arm; `test/format-determinism.test.js` and
`test/no-stray-state.test.js` (which exercise `rules validate`/`rules lock`) still pass.

**Deliberately NOT reused: `posture/evaluation/custody.js`.** An earlier version of the anti-cheating leakage
check imported `protectedTermsFrom`/`guardPrompt` from the evaluation custodian module. `test/evaluation/
custody.test.js`'s `[QA-002.AC03] static isolation` test exists specifically to keep that module unreachable from
anything outside `posture/evaluation/` (it guards the sealed-label trust boundary). Reusing it was the wrong kind
of reuse; `promotion.js` now has its own small, independent leakage check instead.

**Closed in the follow-up (PRD 3 gap closure):**
- All seven listed mutators now exist (variable rename, wrapper, indirection, equivalent API, statement reordering, alternate
  sanitizer, framework variant), and the SAFE side (nearby-clean and protected variants) is mutated as well, so a rule keyed to one
  sanitizer's name fails its protected sibling — `mutation.js`, `corpus.js`, `test/rule-compiler/synthesis.test.js`.
- Automatic pattern proposal and the bounded synthesis loop (propose, compile, positives, negatives, mutation, score, revise,
  repeat, emit a candidate) — `proposal.js`, deterministic, no model call; a model's own proposal is tried first when supplied.
- `labs synthesize-rule <finding-id>` is now the PRD's literal command (it is `rules synthesize`); the older slash-command mode
  `/labs --synthesize-rule` is a different feature and is unchanged.
- Anti-cheating check widened to the PRD's list: benchmark names, advisory ids, vulnerability comments, CWE-bearing and answer-key
  file names; fails closed before anything is written — `promotion.js`, CLI test.
- Provenance record per rule (`provenance.json`): originating finding and commit, evidence state, generating model, prompt
  version, positive and negative corpus hashes, benchmark results, mutator coverage, rule hash and version, promotion event.
- `rules cost <rule-id>`: the business metric (first discovery cost against later deterministic detections at $0 of model spend).
- `rules evaluate` defaults to the corpus the rule was synthesized on.

**Closed in the second follow-up (PRD 3 requirement 2, the IR):**
- The IR's source, propagator, sink, sanitizer, dominating guard, framework constraint, exclusions and language fields are regular
  expressions the matcher enforces. Before this they were free-text hints the matcher ignored, which this page had counted as
  done. They compile into the existing custom-rule matcher, extended additively (`fileRequires`, `guardedBy`/`guardWindow`,
  `excludeLine`) in `posture/custom-rules.js`; a sanitizer is local to the hit it guards.
- Scoring now uses the scanner's own rule normalizer (`normalizeCustomRule`), not a second implementation, and a rule the loader would
  refuse is rejected at compile time. Previously a rule could score well and never fire in a scan.
- The synthesis loop proposes a structural candidate and revises it with the patched code's vocabulary as a local sanitizer.
- Tests: `test/rule-compiler/structure.test.js` (9) and a structured-rule scenario in `test/cli/rule-compiler-cli.test.js` against a
  real spawned CLI and a real scan.

- Requirement 8 (regression integration) is now a mechanism, not only fixtures: a shared false-positive corpus (every promoted rule's
  safe code plus operator files) is part of the gate and of `rules promote`, and `rules regress` re-scores all promoted rules. The
  promoted rule is still not added to this repository's own `bench/` corpora (see the guide for why).

- A defect in the delivered flow, found by re-reading the PRD and trying it without test-only environment overrides: `rules promote`
  published an unsigned pack that the scanner refuses by design, so a "promoted" rule found nothing in a default scan (every test had
  set `AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1`). Now `promote` signs with `--sign-key`, reports whether the scanner will load the rule
  (`NOT LIVE YET` otherwise), and `rules status` shows `live`. Underneath it, `signRulePack` itself was broken on current Node
  ("Invalid JWK OKP key"); fixed and covered by `test/rule-pack-signing.test.js`.

**Still not done:**
- What remains is: no MCP tool surface for synthesis; the anti-cheating check is a pattern
  check on the synthesis material, not a connection to a real benchmark population; a proposal is a regular expression over text
  (no AST or data-flow rule); the mutator tables are small and conservative by design; the later-detection count in `rules cost`
  reads the last scan only.

**Blockers:** none structural.

**Last verified commands (this session):**
- `cd scanner && node --test test/rule-compiler/core.test.js test/cli/rule-compiler-cli.test.js` → 14 pass, 0 fail.
- `cd scanner && node --test test/evaluation/custody.test.js` → isolation test passes (confirms no reach-across).
- `cd scanner && node --test test/format-determinism.test.js test/no-stray-state.test.js` → pre-existing
  `rules validate`/`rules lock` behavior intact after the collision fix.
- `node scripts/verify-doc-examples.mjs` → the rule-compiler guide's commands resolve to real subcommands.
