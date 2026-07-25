# PRD — Proof Corpus: validating the scanner against ten real open-source projects

**Status:** Proposed — nothing in this document is implemented yet.
**Version:** 1.0
**Date:** 2026-07-25
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** A new bench (`bench/proof-corpus/`) that scans ten large, real, third-party open-source repositories and produces independently reproducible evidence about language coverage, detection quality, and operational behaviour at scale.
**Audience:** Engineering (scanner core) primarily; §9 defines the derived artifacts for customer, investor, and marketing audiences.

---

## 1. Purpose

Prove — with reproducible, machine-generated evidence — that the scanner works on real-world code across eight languages, several licence regimes, and codebase sizes from ~100 KLOC to several million lines.

The ten targets:

| Repository | Expected primary languages | Expected licence family |
|---|---|---|
| tryghost/ghost | JavaScript / TypeScript (Node) | permissive |
| grafana/grafana | Go + TypeScript | copyleft (network) |
| apache/superset | Python + TypeScript | permissive (foundation-governed) |
| getsentry/sentry | Python + TypeScript | source-available |
| discourse/discourse | Ruby + JavaScript | copyleft |
| jellyfin/jellyfin | C# (.NET) | copyleft |
| mattermost/mattermost | Go + TypeScript | mixed (copyleft + source-available) |
| jenkinsci/jenkins | Java | permissive |
| nextcloud/server | PHP + JavaScript | copyleft (network) |
| godotengine/godot | C++ | permissive |

**Licence and language columns above are expectations, not assertions.** The runner detects both automatically from the cloned tree (§5.4) and the scorecard reports what was actually found. If a column here turns out wrong, the generated scorecard is the source of truth and this table gets corrected — not the other way round.

---

## 2. Honesty preface

Three things must be stated before any of the design, because they define what this bench can and cannot claim.

**2.1 This is the follow-through on a known open gap.** `docs/SAST_SCA_IMPROVEMENT_PRD.md` §2 states plainly that the current F1 = 1.000 figure is measured on a **185-entry, self-authored corpus where we wrote both the vulnerable and the fixed sample**, and that recommendation **R16 (independent-corpus measurement) is still partial** — the harness exists, a real corpus does not. This PRD is that corpus. Until it lands, quality claims beyond regression protection remain aspirational, and this document does not permit them.

**2.2 A new bench, not an extension of the existing one.** `bench/cve-replay/` entries are deliberately minimal — `CONTRIBUTING.md` requires "one to three files" per entry and the runner reads each as a tiny project. Its own manifest concedes that synthetic shapes "overestimate how well we'd do on the real CVE because the real CVE often had distracting context the synthetic doesn't." Real repositories are exactly that distracting context. Mixing million-line trees into a corpus whose gate assumes minimal fixtures would break the gate's meaning and its runtime. Therefore: `bench/proof-corpus/` is a sibling bench with its own manifest, runner, and baseline. Nothing in `bench/cve-replay/` changes.

**2.3 Language support is not uniform, and the bench must say so.** The IR tree has first-class parsers for JS/TS, Python, Java, Kotlin, Go, PHP, Ruby, and C# (`scanner/src/ir/parser-*.js`), but flow-engine maturity is genuinely deep only for JS, Python, and Java; the rest are primarily structural. C++ has no first-class IR parser at all — it is served by the **optional, off-by-default** tree-sitter path (`AGENTIC_SECURITY_TREE_SITTER=1`, optional `web-tree-sitter` deps, marked `--external` in the build). Godot is therefore the hardest target in the set and the most likely to produce an honest partial result. The scorecard reports a per-language **support tier** (first-class IR / structural IR / tree-sitter opt-in / regex-only) alongside every number, so no reader can mistake "we produced findings" for "we have deep flow analysis here."

---

## 3. Goals and non-goals

### 3.1 Goals

- **G1 — Breadth.** All ten repositories scan to completion, deterministically, within a declared per-repo budget, emitting findings, SBOM, and SARIF.
- **G2 — Real detection.** For a strategic subset, demonstrate `pre:TP post:TN` against **already-public, already-patched CVEs** in those projects, using the projects' own release tags.
- **G3 — Honest measurement.** Publish parse coverage, finding density, and support tier per language per repo — including where they are weak.
- **G4 — Zero manual work.** The entire campaign is one command, re-runnable, with no human triage step anywhere in the pipeline.
- **G5 — Reusable regression asset.** The bench becomes a gated, periodically re-run artifact, not a one-off marketing exercise.

### 3.2 Non-goals

- **Not a vulnerability disclosure programme.** We do not publish, report, or act on findings against the current HEAD of any of these projects (§8.1).
- **Not a competitive benchmark.** This bench measures the scanner against itself over time and against ground truth. It makes no comparative claim about any other product, and no other product is named in this bench, its outputs, or its commits.
- **Not a fix/remediation exercise.** `/fix`, PoC generation, and the LLM validator are out of scope for v1. Scanning, parsing, and reporting only.
- **Not a build integration.** We never compile these projects. We parse source trees. This is what makes historical tag checkout cheap and reliable.

---

## 4. Tiering

### 4.1 Tier 1 — deep dive (4 repos)

Chosen for language spread across the three deepest-supported flow-engine languages plus the newest parser tier, and for having substantial public advisory history:

| Repo | Language proved | Why this one |
|---|---|---|
| jenkinsci/jenkins | Java | Deepest Java flow support; long, well-documented advisory history with clean fix tags |
| grafana/grafana | Go + TypeScript | Proves the Go parser on a large production codebase; dual-language repo |
| apache/superset | Python + TypeScript | Deepest Python flow support; foundation governance; well-tagged releases |
| discourse/discourse | Ruby | Exercises the least-proven first-class parser; strongest signal per unit of effort |

Tier 1 gets: everything Tier 2 gets, **plus** CVE replay (§6).

### 4.2 Tier 2 — breadth pass (6 repos)

Ghost (JS/TS), Sentry (Python), Mattermost (Go), Jellyfin (C#), Nextcloud (PHP), Godot (C++).

Tier 2 gets: scan-to-completion, operational metrics, parse coverage, language and licence attribution, SBOM, determinism check. **Findings content is collected but not published** (§8.1).

Tier 2 is where the surprising failures will surface — Jellyfin and Godot in particular. That is the point of including them.

---

## 5. Design — the breadth pass

### 5.1 Layout

```
bench/proof-corpus/
  manifest.json          # the ten targets, pinned commits, tier, budgets, scope filters
  runner.mjs             # orchestrator + CLI
  lib/
    clone.mjs            # blobless shallow fetch at a pinned SHA, into an out-of-tree cache
    scan.mjs             # invoke the bundled CLI, capture exit code / timing / RSS
    irstats.mjs          # parse-coverage extraction (needs the Phase 0 scanner flag)
    licence.mjs          # SPDX / LICENSE / package-metadata detection
    replay.mjs           # Tier-1 CVE replay driver (§6)
    report.mjs           # scorecard + per-repo case-study markdown emitters
  replay/<repo>/<cve-id>/manifest.json   # one file per replay case; no fixture source
  results/               # timestamped run output (gitignored except the committed summary)
  baseline.json          # gated expectations
  README.md
  CONTRIBUTING.md
```

Clones live at `~/.claude/agentic-security/proof-corpus-cache/`, **never inside the repo**. Nothing third-party is ever committed. This also keeps the licence surface clean: we hold no copy of AGPL or source-available code in our tree.

### 5.2 Acquisition

Per target: `git init` → `git remote add origin <url>` → `git fetch --depth 1 --filter=blob:none origin <pinned-sha>` → `git checkout FETCH_HEAD`.

Pinning to a full SHA rather than a branch is what makes the whole campaign reproducible — a re-run six months from now produces the same numbers. A `--refresh-pins` mode re-resolves each default branch to its current tip and rewrites the manifest, so pin advancement is a deliberate, reviewable act rather than silent drift.

Disk budget is real: ten repos with blobless clones plus Tier-1 historical tags will run into the several-gigabyte range. The runner reports cache size and supports `--prune-cache`.

### 5.3 Scanning

The bundled CLI (`dist/agentic-security.mjs`) is invoked — not `src/` — because the bundle is what users actually run, and a bench that passes on `src/` while the bundle is stale would be exactly the class of false confidence the root `CLAUDE.md` verification rules exist to prevent. The runner asserts the bundle's SHA-256 sidecar matches before starting, and refuses to run against a stale bundle.

Fixed invocation per repo: `--deterministic`, deep taint on, tree-sitter on where the manifest requests it, SBOM and SARIF emit on, OSV cache warm.

Each repo declares in the manifest:
- `time_budget_s` — wall-clock ceiling; exceeding it is a **recorded failure**, not a silent skip
- `scope` — optional subtree filter (e.g. Godot may scan `core/`, `modules/`, `scene/` rather than the full tree including thirdparty vendored code). Any scope narrowing is declared in the manifest, printed in the run log, and reproduced verbatim in the scorecard. **Silent scope reduction is prohibited** — an unscoped claim over a scoped scan is the single most dishonest thing this bench could do.

### 5.4 Metrics collected per repo

| Metric | Definition | Proves |
|---|---|---|
| **Parse coverage** | files that produced an IR record with ≥1 function ÷ files in scope for that extension | *Actual* language support, as distinct from extension recognition. The headline metric. |
| Support tier | first-class IR / structural IR / tree-sitter opt-in / regex-only, per language | Honest framing of every other number |
| Language mix | LOC and file count per language | That the target exercises the languages claimed |
| Licence | detected SPDX identifier(s) + source of detection | Licence-regime breadth |
| Scan wall time, peak RSS | measured by the runner, not self-reported | Operational viability at scale |
| Finding count by severity, and per KLOC | normalised density | Noise level; cross-repo comparability |
| Parser attribution | distribution of `finding.parser` | That findings come from the language engines we claim |
| SBOM component count, ecosystems | from the emitted SBOM | Supply-chain pipeline works on real manifests |
| Determinism | two consecutive runs → byte-identical SARIF | The `--deterministic` contract holds on real input |
| Exit code | captured explicitly | Gate-ability |

**Parse coverage requires a scanner change.** No current flag exposes per-file IR success. Phase 0 adds `AGENTIC_SECURITY_IR_STATS=<path>`, which writes a per-language `{inScope, parsed, functions, failures[]}` sidecar. This is a small, additive, default-off instrumentation surface — and it is independently useful beyond this bench.

---

## 6. Design — Tier-1 CVE replay

This is the part that proves detection rather than execution, and it is designed so that **no human ever writes a fixture or triages a finding.**

### 6.1 The mechanism

For each replay case the manifest records only: the CVE identifier, the advisory URL, the **vulnerable tag**, the **fixed tag**, and the expected CWE/family match. Everything else is derived:

1. Check out the fixed tag; check out the vulnerable tag.
2. Compute the patch's source-file set automatically: `git diff --name-only <vulnerable-tag> <fixed-tag>`, filtered to source extensions and to files the advisory's patch actually touched. **This derived file set is the ground truth for "where the bug is"** — the project's own maintainers defined it when they wrote the fix.
3. Scan the vulnerable tree. **Pass condition (pre:TP):** at least one finding whose `file` is in the derived set and whose `vuln` / `family` / `cwe` matches the expected pattern.
4. Scan the fixed tree. **Pass condition (post:TN):** that finding is gone — matched by `stableId`, falling back to (file, rule, CWE) when the patch moved lines.

Deriving ground truth from the maintainers' own patch is what removes the manual step. We are not asserting where the vulnerability is; the upstream fix commit is.

### 6.2 Case selection — also automated

Rather than hardcoding CVE identifiers into this document (which would bake in whatever I believe today and be wrong somewhere), Phase 3 begins with a **discovery step**: for each Tier-1 repo, enumerate published advisories from the project's own security advisory feed, and keep only cases that satisfy every mechanical filter:

- CWE falls in a family the scanner claims to detect
- The fix is tagged in a public release, and both tags fetch cleanly
- The patch touches ≤ 25 source files (large refactor-shaped fixes make the derived ground truth too loose to mean anything)
- The vulnerable code is in a language with a first-class IR parser in that repo

Every candidate that survives becomes a replay case. Its result — pass, miss, or post-fix false positive — is recorded either way.

**Target: ≥ 2 replay cases per Tier-1 repo, ≥ 8 total.** A repo where zero candidates survive the filters is itself a reportable finding about coverage, and is recorded as such rather than quietly dropped.

### 6.3 Misses are the valuable output

A `pre:FN` (we did not detect a real, disclosed CVE in real code) is the highest-signal output this entire campaign can produce. Each one becomes a rule-development ticket in the gap register (§7.2) with the patch diff attached. Per `bench/cve-replay/CONTRIBUTING.md`'s tiering philosophy, replay cases are **capability-tier by default** — informational, non-blocking — and graduate into the gated baseline only once they pass.

---

## 7. Outputs

### 7.1 Committed artifacts

- `bench/proof-corpus/results/summary.json` — aggregate metrics only, no finding content
- `bench/proof-corpus/baseline.json` — gated expectations (§7.3)
- `docs/proof/SCORECARD.md` — generated roll-up across all ten
- `docs/proof/<repo>.md` — generated per-repo case study (ten files)

All four are **generated**, never hand-edited. A hand-edited scorecard is a fabricated one.

### 7.2 Gap register

`docs/proof/GAPS.md`, also generated: every miss, every timeout, every low-coverage language, every repo where advisory filtering yielded nothing. This file existing and being non-empty is a feature. A campaign of this size that reports zero gaps has a broken harness, not a perfect scanner.

### 7.3 Gating

`bench:proof-corpus:check` compares a fresh run against `baseline.json` and fails on regression in: repo scan success, parse coverage (beyond a per-language tolerance band), determinism, or any replay case that has graduated to gated status. Same update discipline as the existing corpus: change → check → `update-baseline` → commit the regenerated baseline.

Because these runs are long and network-dependent, the gate is **not** wired into `npm test`. It runs on demand and on a schedule.

---

## 8. Risks and mitigations

### 8.1 Disclosure risk — the one that matters most

Scanning ten live third-party projects produces unreviewed findings against software real people run in production. Publishing those would be irresponsible, and would also be *bad evidence*, since unreviewed static findings on well-maintained code are mostly hardening opportunities rather than vulnerabilities.

**Mitigation, enforced by the harness rather than by discipline:** the report emitters have no access to finding content for HEAD scans — they consume only aggregate counts. Raw findings JSON is written under `results/raw/`, which is gitignored, and the runner refuses to emit a case study containing a file path from a HEAD scan. Published detection evidence comes exclusively from CVE replay, where the vulnerability is already public and already patched.

If a HEAD scan does surface something that looks like a genuine, serious, previously-unknown vulnerability, that is a human decision through the project's own security contact — deliberately outside this automated pipeline, and explicitly out of scope for the published artifacts.

### 8.2 Licence risk in published artifacts

The set spans permissive, copyleft, network-copyleft, and source-available licences. We never redistribute code (§5.1 keeps clones out of the tree), but *case studies quoting source* would be a redistribution question, particularly for the source-available targets.

**Mitigation:** generated case studies contain no source excerpts at all — only file paths, line numbers, CWE identifiers, and counts. This costs nothing evidentially and removes the question entirely.

### 8.3 Scale

Godot and Nextcloud are large enough that timeout or memory exhaustion is a plausible outcome. Mitigations, in order: declared per-repo time budget; incremental and parallel scan flags; declared subtree scope. All three are visible in the scorecard. A repo that can only be scanned scoped is reported as *scanned scoped* — which is still a useful, honest result, and a performance ticket.

### 8.4 C++ coverage is conditional

Godot depends on the optional tree-sitter path, which is off by default and requires optional dependencies the shipped bundle deliberately does not embed. The likely honest outcome is "C++ produces structural findings with low parse coverage and no deep flow analysis." The scorecard states this in those words. Overstating C++ support would poison the credibility of the nine results that *are* strong.

### 8.5 Network dependence

SCA needs OSV; replay discovery needs advisory feeds; cloning needs GitHub. All are rate-limitable and all can be down. Mitigation: warm the OSV disk cache before the run, snapshot advisory query results into the replay manifests at discovery time so re-runs need no advisory API, and provide `--offline` which runs everything possible from cache and marks the rest `skipped-offline` rather than passing or failing it.

### 8.6 Upstream drift

Tags get deleted, repos get renamed or archived. Pinned SHAs plus the local clone cache absorb most of this; `--refresh-pins` makes advancement explicit.

---

## 9. Audience mapping

One generated evidence base, four framings — none of which introduce a claim the harness did not measure:

| Audience | Artifact | Core claim it supports |
|---|---|---|
| Customers | `docs/proof/SCORECARD.md` — language × licence × scale matrix | "It runs on code like yours, whatever you write it in" |
| Investors | Replay results section of the scorecard, plus §2's honest framing | "It finds real, disclosed vulnerabilities in real production code — and we measure ourselves honestly enough to publish where it doesn't" |
| Internal quality | `GAPS.md` + the gated baseline | Prioritised, evidence-backed rule and performance backlog |
| Marketing | Per-repo case studies | Ten concrete, named, verifiable reference points |

The investor framing is deliberately the one that leads with the limitation. A scorecard that admits C++ is shallow and that lists its misses is far more credible than one that does not — and it is the only version consistent with §2.

---

## 10. Phasing

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0 — Instrumentation** | `AGENTIC_SECURITY_IR_STATS` sidecar; licence detector | Unit-tested; parse coverage computable on an existing fixture |
| **1 — Harness skeleton** | `manifest.json`, `clone.mjs`, `scan.mjs`, runner CLI; two easy targets (Ghost, Superset) | Both scan end-to-end; metrics emitted; determinism check passes |
| **2 — Breadth pass** | All ten targets; scorecard v1; gap register | Every repo has a recorded outcome — success, scoped success, or explicit failure |
| **3 — Replay** | Advisory discovery + replay driver; Tier-1 cases | ≥ 8 replay cases executed with recorded verdicts |
| **4 — Reporting** | Case-study and scorecard emitters | All eleven documents generated, zero hand-editing |
| **5 — Gating** | `baseline.json`, `bench:proof-corpus:*` scripts, scheduled run | Gate proven in both directions: passes clean, fails on injected regression |

Phase 1 deliberately proves the harness on the two easiest targets before spending time on the hard ones. Phase 2 can publish before Phase 3 exists — breadth evidence stands on its own.

### 10.1 New npm scripts (`scanner/package.json`)

```
bench:proof-corpus                  node ../bench/proof-corpus/runner.mjs
bench:proof-corpus:breadth          … --tier breadth
bench:proof-corpus:replay           … --tier replay
bench:proof-corpus:check            … --check-baseline
bench:proof-corpus:update-baseline  … --update-baseline
bench:proof-corpus:report           … --emit-report
```

---

## 11. Acceptance criteria

The campaign is complete when all of the following are **verified by a command run in the same session as the claim** (root `CLAUDE.md` verification discipline applies in full):

1. 10/10 repos have a recorded terminal outcome; ≥ 8/10 scan successfully within budget, unscoped or with a declared scope.
2. Parse coverage ≥ 85% for every language on a first-class IR parser, measured on a real repo. Languages below that threshold are listed in `GAPS.md` with the failing files.
3. 10/10 repos produce byte-identical SARIF across two consecutive runs.
4. 10/10 repos have an auto-detected licence and language mix in the scorecard.
5. ≥ 8 replay cases executed across the 4 Tier-1 repos, each with a recorded `pre` and `post` verdict. **The pass rate is reported, not required** — a low pass rate is a valid, publishable, honest outcome that generates backlog.
6. `bench:proof-corpus:check` demonstrated to exit 0 on a clean run and non-zero on a deliberately corrupted baseline.
7. Eleven generated documents exist and contain no hand-written numbers.
8. No published artifact contains a finding against any repo's HEAD, and no published artifact contains third-party source.

---

## 12. Open questions

1. **Scheduled cadence** — weekly or monthly? Ten large scans is real compute. Recommendation: monthly, plus on-demand before a release that touches IR or detectors.
2. **Do replay cases graduate into `bench/cve-replay/`?** Recommendation: no. Keep the two benches separate — one synthetic and fast enough to gate CI, one real and slow. Cross-reference instead of merging.
3. **Godot scope** — full tree including vendored `thirdparty/`, or first-party only? Recommendation: first-party only, declared, with a note that vendored code is an SCA concern rather than a SAST one.
