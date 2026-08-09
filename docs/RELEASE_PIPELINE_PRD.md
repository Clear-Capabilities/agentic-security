# Release Pipeline PRD — cost, coverage, and provenance

**Status:** proposed · **Owner:** unassigned · **Created:** 2026-08-09
**Engine version at authoring:** 0.134.0

---

## 1. Problem

`npm publish` is slow, blocks on signals that are not correctness signals, and
leaves two things unverified that this project's own positioning claims to care
about.

Every figure below was measured on the maintainer's machine on 2026-08-09, not
estimated.

### 1.1 The same facts are derived three times per commit

`npm test` and `bench:cve-replay:check` run in **all three** of the pre-push
gate, hosted CI (`.github/workflows/ci.yml`), and `release-check.mjs`.

| Stage | Wall clock | Trigger |
|---|---|---|
| pre-push gate | 155–200 s | every `git push` |
| hosted CI | parallel, ~1–4 min/job | every push |
| `release-check` (via `prepublishOnly`) | ~290 s | every `npm publish` |

A push-then-publish on one immutable commit costs roughly **8 minutes of local
wall clock** re-deriving identical facts. This is not a safety/speed trade — the
inputs are byte-identical, and this engine already asserts determinism over
exactly those inputs (`posture/attestation.js`, `scan-checkpoint.js`'s run key).

### 1.2 Release-check breakdown

| Check | Cost | Notes |
|---|---|---|
| `npm run build` | 8 s | precedes release-check in `prepublishOnly` |
| `test-suite` | **210 s** | 72 % of the gate |
| `self-scan-gate` | 61 s | |
| `corpus-gate` | 18 s | |
| `working-tree-clean`, `version-consistency`, `changelog-entry`, `bundle-integrity`, `scorecard-freshness` | ~0 s | |
| `head-pushed`, `remote-ci-green` | network, seconds | |
| `dependency-currency` | see §5 | measured 1 s only because it short-circuited |

### 1.3 Inside the 210 s test suite

| Script | Cost | Files |
|---|---|---|
| `test:glob` | **52 s** | one file — `glob-compat.test.js` |
| `test:sast` | 47 s | detector suite |
| `test:posture` | 40 s | posture suite |
| `test:smoke` | 30 s | one file — `smoke.test.js` |
| all others combined | 35 s | |

Two are anomalies rather than large suites: `glob-compat.test.js` is 184 lines
and 13 tests exercising a path-matching primitive, and `scanner/CLAUDE.md`
describes `test:smoke` as "one-file fixture, fast" and the thing to run "after
any change anywhere" — a description that has drifted from a 30 s reality.

### 1.4 A publish blocked on a non-correctness signal

On 2026-08-09 a publish was blocked for 15+ minutes by `remote-ci-green` while
**8 of 9** CI checks were green. The outstanding job was `realworld-bench`
(Juice Shop / Snyk Goof / NodeGoat detection rates). That job measures a quality
*trend*; it does not decide whether the current build is publishable.

### 1.5 Two unverified things

- **Package contents.** Nothing checks what actually ships. `files` is
  `["src/","bin/","dist/","CHANGELOG.md","!**/.agentic-security","!**/.agentic-security/**"]`
  — so both source and the built bundle ship. A bad `files` edit, a stray
  artifact, or an accidentally-included state directory publishes silently.
- **Publish provenance.** The published artifact carries no npm provenance
  attestation. Publishing is **manual and local** — there is no publish
  workflow — so there is currently no path to one. For a project whose
  positioning is signed, verifiable evidence, this is the least defensible gap
  in the list.

---

## 2. Goals

1. Cut `npm publish` wall clock from ~5 minutes to **under 60 seconds** on an
   unchanged, already-pushed commit, **without removing a single check**.
2. Stop non-correctness signals from blocking a release.
3. Verify what is actually published, and publish it with provenance.
4. Preserve every existing guarantee, including the rule that an unrunnable
   check is a failure.

## 3. Non-goals

- Weakening, removing, or making optional any of the eleven checks.
- Putting `--fast` into `prepublishOnly`. `release-check.mjs`'s own header
  forbids it: *"the fast path must never be the publish path… the correct fix is
  to make the slow gates faster."* This PRD is that fix.
- Changing what the corpus or self-scan baselines assert.
- Reducing hosted-CI coverage. R2 changes what **blocks a publish**, not what
  runs.

## 4. Constraints that bind every workstream

These are existing project rules. A change that violates one is rejected
regardless of the time it saves.

- **C1 — Unrunnable is a failure, never a skip.** A cache that cannot be read,
  a manifest that cannot be produced, a registry that cannot be reached: all
  fail closed.
- **C2 — Unverified is not green.** Applies to a cached verdict exactly as it
  applies to hosted CI.
- **C3 — Silence is not success.** Anything skipped, cached, or degraded is
  printed, with provenance.
- **C4 — No new runtime network dependencies** in the scanner itself.
- **C5 — No external tool names** in source, docs, or commit messages.
- **C6 — Determinism.** Nothing may introduce a clock or randomness into an
  identity, digest, or sort key.

---

## R1 — Cache slow-gate verdicts by input hash

**Priority:** P0 · **Est. saving:** ~290 s → ~5 s on an unchanged commit

### Problem
`release-check` re-runs `test-suite`, `corpus-gate`, and `self-scan-gate` on a
commit the pre-push gate verified minutes earlier, with byte-identical inputs.

### Proposal
A verdict cache keyed on the full set of inputs that could change an outcome.
When a check has a valid cached PASS for the current key, release-check accepts
it and prints where the verdict came from.

### Design

**Key** (all components required; a missing component invalidates):

```
commit SHA          git rev-parse HEAD
tree SHA            git rev-parse HEAD^{tree}   (catches a dirty tree)
bundle SHA-256      dist/agentic-security.mjs.sha256
ruleset version     posture/ruleset-version.js
node version        process.version
platform+arch       process.platform + process.arch
env fingerprint     sorted AGENTIC_SECURITY_* names and values
```

Precedent: `scan-checkpoint.js` already builds a comparable run key and
discards on any drift. Reuse its shape and its philosophy — *redoing work is
slow; resuming stale work is a correctness bug.*

**Storage:** `.agentic-security/gate-verdicts.json`, gitignored. One record per
`{checkId, key}` with `verdict`, `at`, `by` (`pre-push` | `release-check`),
`durationMs`. Written by whichever gate ran the check.

**Only PASS is cached.** A failure is never cached — a developer fixing a
failure must be able to re-run without clearing state, and a cached FAIL would
create a confusing "still failing after I fixed it" loop.

**TTL:** 24 h, as a backstop against a machine-state change the key does not
model (an OS upgrade, a rotated toolchain). Expiry means re-run, not fail.

**Output (C3):** a cached check prints its provenance instead of pretending to
have run:

```
PASS  Full test suite passes
      ↳ cached: verified 14:31:02 by pre-push gate for 24e8609 (210s), key age 4m
```

**Escape hatches:** `--no-cache` forces every check to run;
`AGENTIC_SECURITY_GATE_NO_CACHE=1` does the same for CI.

### Acceptance criteria
- [ ] Publishing an unchanged, already-pushed commit runs zero slow gates and completes in < 60 s.
- [ ] Touching any file in `scanner/src/` invalidates and re-runs all three.
- [ ] Editing `scanner/src/` **without rebuilding** invalidates (bundle SHA differs) — the "forgot to rebuild" case must not be cacheable.
- [ ] Changing an `AGENTIC_SECURITY_*` value invalidates.
- [ ] A corrupt/unreadable/truncated cache file causes a full re-run, never a pass (**C1**).
- [ ] A cached PASS is visually distinct and states when, by whom, and for which SHA (**C3**).
- [ ] `--no-cache` reproduces today's behaviour exactly.
- [ ] A FAIL is never written to the cache.
- [ ] Unit tests cover: key stability across two identical runs; key change per component (one test per component); expiry; corruption; PASS-only.

### Risks
| Risk | Mitigation |
|---|---|
| A cached pass hides an environment change the key does not model | Node/platform/arch/env in key, plus 24 h TTL, plus `--no-cache` |
| Cache file becomes a trusted input an attacker could forge | It is local, gitignored, and only ever *skips work already done on this machine*. Sign with the existing per-install HMAC (`posture/integrity.js`) so tampering is detectable — reuse, do not invent a second key mechanism |
| Developers stop trusting a green gate | The provenance line is mandatory, not optional |

### Out of scope
Sharing the cache between machines or with CI. A cross-machine cache needs the
cross-machine reproducibility claim this project explicitly does **not** make
(`posture/attestation.js` header).

---

## R2 — Long benchmarks stop blocking a release

**Priority:** P0 · **Est. saving:** removes an unbounded 15 min+ block

### Problem
`remote-ci-green` requires **every** check on the commit. `realworld-bench` is a
long benchmark measuring detection rate against public vulnerable apps. It is a
trend signal, not a correctness gate, and it blocked a publish for 15+ minutes
while everything else was green.

### Proposal
Split hosted checks into **blocking** and **informational**, and require only
the blocking set.

**Blocking** (correctness — a red here means do not ship):
`ci` · `corpus` · `sandbox-linux` · `determinism-attest` (both OS) ·
`determinism-compare` · `codeql` / `analyze`

**Informational** (trend — a red here means investigate, not "stop the release"):
`realworld-bench` · `synthetic-bench` · `Scanner F1 benchmark`

### Design
- Add a `blocking: true|false` classification, sourced from a single committed
  list (`.github/required-checks.json`) so the gate and branch protection cannot
  disagree.
- `remote-ci-green` requires all **blocking** checks green; it **reports**
  informational check status without gating.
- An informational check that is *failing* (not merely pending) prints a loud
  warning at publish time. Trend regressions must not become invisible — that
  would trade one silent failure for another.
- Move `bench.yml`'s long jobs to `schedule:` plus manual dispatch, so they
  still run regularly and alert on drop, without sitting in the release path.
- Update branch protection to require exactly the blocking set. **This also
  removes the routine "Bypassed rule violations" that every recent `main` push
  has produced** — a protection rule that is habitually bypassed is not a
  control.

### Acceptance criteria
- [ ] A publish proceeds when all blocking checks are green and an informational one is pending.
- [ ] A publish is blocked when any blocking check is red or pending.
- [ ] A *failing* informational check prints a warning naming it, and does not block.
- [ ] The required set is defined once and consumed by both the gate and branch protection; a drift test fails if they disagree.
- [ ] Pushing to `main` no longer reports bypassed rule violations.
- [ ] `docs/` records why each check is in its tier.

### Risks
| Risk | Mitigation |
|---|---|
| A real regression hides in an informational check | Failing (vs pending) informational checks warn loudly at publish; scheduled runs alert independently |
| Tier list rots as jobs are added | Drift test: every check-run name observed on `main` must appear in the classification, else fail |

---

## R3 — Make the test suite fast enough that R1 is a bonus

**Priority:** P1 · **Est. saving:** target 210 s → < 90 s

### Problem
Four scripts are 169 s of 210 s. Two are single files doing far more work than
their subject warrants. Because the suite runs in three places, every second
saved pays out three times per commit.

### Proposal
Profile first, then fix. **No test may be deleted or weakened to hit the
target** — this is about removing waste, not coverage.

**R3a — `glob-compat.test.js` (52 s, 13 tests).** It exercises `listFiles`,
`globFiles`, and `matchesAnyGlob` against real temp directory trees. 4 s per
test for a path-matching primitive is not inherent. Profile to determine which
of these it is: per-test tree construction with many small `writeFileSync`
calls; unnecessarily large fixture trees; a genuinely slow `prepare`/`prepPath`
glob path (**a performance bug in shipped code, which would be the most valuable
possible outcome**); or missing shared setup across tests.

**R3b — `smoke.test.js` (30 s).** Either bring it back to its documented "fast"
role, or correct `scanner/CLAUDE.md`, which currently tells contributors to run
it after every change. The doc and the reality must agree.

**R3c — `test:sast` (47 s) and `test:posture` (40 s).** These are genuinely
large suites. Do not restructure them under this PRD; measure per-file cost and
record the top five in the PRD's follow-up section for separate work.

**R3d — concurrency, last.** Only after R3a/R3b. `npm test` chains scoped
scripts with `&&`, sequentially. Running independent scopes concurrently is real
wall-clock savings, but it raises load — and load sensitivity is exactly what
produced the `autopilot-cli` failure fixed in `fb85213`. **Do not enable
concurrency until the suite is demonstrably load-insensitive:** run the full
suite 10× under artificial CPU load with zero flakes first.

### Acceptance criteria
- [ ] A profile of `glob-compat.test.js` is recorded, naming the dominant cost.
- [ ] `test:glob` < 10 s with all 13 tests passing and none weakened.
- [ ] `test:smoke` < 10 s, **or** `scanner/CLAUDE.md` updated to describe it accurately.
- [ ] Total `npm test` < 90 s.
- [ ] If a shipped-code performance bug is found, it is fixed and given a regression test.
- [ ] R3d only: 10 consecutive full-suite runs under load, zero flakes, before concurrency is enabled.

### Risks
| Risk | Mitigation |
|---|---|
| "Speed up" becomes "test less" | Test count and assertion count must not drop; reviewer checks the diff for deletions |
| Concurrency reintroduces load flakes | Gated behind the 10× clean-run requirement |

---

## R4 — `dependency-currency` must be self-sufficient

**Priority:** P1

### Problem
The check inspects two trees, `scanner/` and `ide/vscode/`. When
`ide/vscode/node_modules` is absent it reports the tree UNVERIFIED and fails —
correctly, per **C2**. But a publisher on a fresh clone then hits a hard failure
that is about their environment, not their code, with no obvious remedy.

### Proposal
Keep the rule. Remove the footgun.

- Detect the missing tree and **install it automatically** as part of the check
  (`npm ci --prefix ide/vscode --ignore-scripts`), then proceed.
- If the install fails (offline, registry down), fail with the existing
  UNVERIFIED message plus the exact command to run. Never pass.
- Print the install as work being done, so a 40 s first run is explained rather
  than mysterious.
- Cache under R1 like any other check, so it is paid once per key.

### Acceptance criteria
- [ ] From a fresh clone with no `ide/vscode/node_modules`, the check installs and completes.
- [ ] With the network unavailable and the tree missing, it FAILS with an actionable message (**C1/C2**).
- [ ] The auto-install prints before it runs.
- [ ] `--ignore-scripts` is used — this must not execute install hooks from a dependency tree during a release gate.

### Risks
| Risk | Mitigation |
|---|---|
| Auto-install runs untrusted lifecycle scripts | `--ignore-scripts`, `npm ci` against the committed lockfile |
| Masks a genuinely broken tree | Install failure fails the gate |

---

## R5 — Verify what actually ships (gap)

**Priority:** P0 · **New check:** `package-contents`

### Problem
Nothing verifies the published file set. `files` ships `src/`, `bin/`, `dist/`,
and `CHANGELOG.md`, with negations for `.agentic-security`. A bad edit to
`files`, a new directory that should not ship, or a state directory slipping
past the negation would publish silently. This is the only part of the release
where the artifact itself is unexamined.

### Proposal
A check that diffs the actual pack manifest against a committed expectation.

### Design
- Produce the real manifest: `npm pack --dry-run --json` (no tarball written).
- Compare against `scanner/expected-package-manifest.json`, committed and
  reviewed.
- **Compare shape, not bytes.** Assert: the set of top-level directories; that
  no path matches a forbidden pattern (`**/.agentic-security/**`, `**/*.log`,
  `**/node_modules/**`, `**/.env*`, `**/.superpowers/**`, `**/.claude/**`); that
  the bundle and its `.sha256` sidecar are both present; that total file count
  is within a declared tolerance.
- File-count tolerance rather than an exact list: an exact list would need
  regenerating on every added source file, which trains people to refresh it
  without reading it — the same anti-pattern `scripts/attest-fixture.mjs`
  documents for checked-in digests. Directory set and forbidden patterns are
  exact; count is bounded.
- On failure, print the added/removed paths, not just a count.

### Acceptance criteria
- [ ] Check runs in `release-check` and in the pre-push gate.
- [ ] Adding a stray `.agentic-security/` file under `src/` fails the check.
- [ ] Removing `dist/` from `files` fails the check.
- [ ] Adding one ordinary source file passes (within tolerance).
- [ ] Adding 200 files fails and names them.
- [ ] Failure output lists specific paths.
- [ ] Manifest generation failure = check failure (**C1**).

### Risks
| Risk | Mitigation |
|---|---|
| Tolerance too loose to catch anything | Directory set and forbidden patterns are exact; only count is toleranced |
| Expectation file rots | It changes only when the package shape genuinely changes, which should be rare and reviewable |

---

## R6 — Publish with provenance (gap)

**Priority:** P1 · **Largest change in this PRD**

### Problem
The published package has no provenance attestation. A consumer cannot verify
that `@clear-capabilities/agentic-security-scanner@0.134.0` was built from this
repository at a known commit. This project ships signed scan attestations, a
per-install HMAC over `last-scan.json`, and a reproducibility scorecard — and
then publishes itself with none of that. It is the most quotable gap on the
list.

**Publishing is currently manual and local — there is no publish workflow at
all.** npm provenance requires a trusted CI publisher with OIDC, so this is not
a flag; it is a new release path.

### Proposal
A `release.yml` workflow that publishes from CI with `--provenance`, triggered
by a version tag.

### Design
- Trigger: push of a `v*` tag.
- Steps: checkout at the tag → install → **run the full release gate with
  `--no-cache`** (CI is a different machine; R1's cache must not apply) → build
  → `npm publish --provenance --access public`.
- Auth: npm granular token in repository secrets, or trusted publishing if
  available. `id-token: write` permission for OIDC.
- The local `prepublishOnly` gate stays exactly as it is: a developer who runs
  `npm publish` locally still gets fully gated. This adds a preferred path; it
  does not remove the existing one.
- Document both paths in `CLAUDE.md` and `README.md`, and state plainly which
  one produces provenance.

### Acceptance criteria
- [ ] Tagging `vX.Y.Z` publishes that version from CI.
- [ ] The published package shows a provenance attestation on npm.
- [ ] The workflow runs the full gate with caching disabled; a red gate blocks the publish.
- [ ] A tag whose version disagrees with `scanner/package.json` fails before publishing.
- [ ] Local `npm publish` still works and is still gated.
- [ ] Docs state which path yields provenance and that the local path does not.

### Risks
| Risk | Mitigation |
|---|---|
| CI publish token is a new high-value secret | Granular token scoped to this package; prefer trusted publishing; never expose to PR-triggered workflows |
| A tag publishes something unreviewed | Tag only reachable commits on `main`; gate runs in full |
| Divergence between local and CI publish | Both call the same `release-check.mjs`; only caching differs |

---

## 5. Sequencing

```
R5 (package-contents) ─┐
R4 (dep-currency)     ─┼─> R1 (verdict cache) ──> R6 (CI publish + provenance)
R2 (check tiers)      ─┘
R3 (suite speed) ── independent, any time
```

- **R5, R4, R2 first.** Each is self-contained, and R5/R4 add or change checks —
  landing them before R1 means the cache is built against the final check set.
- **R1 next.** It caches whatever checks exist, so it should follow changes to
  the set.
- **R6 last.** It depends on the gate being fast and correctly tiered.
- **R3 in parallel.** Touches nothing the others touch.

## 6. How we will know it worked

Measure before and after with the same method used in §1 (`date +%s` around each
stage, on the maintainer's machine, on an unchanged and already-pushed commit).

| Metric | Now | Target |
|---|---|---|
| `npm publish` on an unchanged pushed commit | ~290 s + 8 s build | **< 60 s** |
| `npm publish` on a changed commit | ~290 s | < 150 s (R3) |
| `npm test` | 210 s | < 90 s |
| `test:glob` | 52 s | < 10 s |
| Publish blocked on a non-correctness signal | yes, 15 min+ observed | never |
| Checks removed or weakened | — | **zero** |
| Package contents verified | no | yes |
| Published artifact carries provenance | no | yes |

## 7. Rollback

Each workstream is independently revertible.

- **R1** — delete the cache file and pass `--no-cache`; behaviour is identical to today. Revert is one commit.
- **R2** — restore the previous required-check list in branch protection.
- **R3** — pure performance work; revert restores the slower tests.
- **R4** — revert restores the manual-install requirement.
- **R5** — a new check; removing it returns to today's unverified state.
- **R6** — the local publish path is untouched throughout, so a broken CI publish never leaves the project unable to publish.

## 8. Open questions

1. **TTL length for R1.** 24 h is a guess. If the team never sees a stale-cache surprise in a month, consider raising it; if one is seen, model the missing input in the key rather than shortening the TTL.
2. **Should the pre-push gate also cache?** It has the same redundancy across repeated pushes. Deferred — measure first; pushes are less frequent than the push+publish pair.
3. **`test:sast` / `test:posture` (87 s combined).** Genuinely large suites. Needs its own investigation; explicitly out of scope here (R3c).
4. **Trusted publishing vs. granular token for R6.** Prefer trusted publishing if the registry supports it for this scope; decide at implementation.

## 9. Follow-ups explicitly not in this PRD

- Per-file cost breakdown of `test:sast` and `test:posture` (R3c).
- Giving `struct:` detector findings a `line`, which would let ignore pragmas suppress them (documented limitation in `engine.js#_applyIgnorePragmas`).
- Cross-machine gate-verdict sharing (requires a reproducibility claim this project does not make).
