# SARD 80% F1 Execution PRD — Implementation Ledger

Source: `SARD_80_F1_EXECUTION_PRD.md` (repo root, untracked per this repo's PRD
convention — ask the maintainer for the current copy if missing). This ledger
is the persistent execution record for that PRD, maintained by an autonomous
`/loop` session. Status values: `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`,
`IMPLEMENTED_UNVERIFIED`, `VERIFIED`.

**Rule (same as the sibling `IMPLEMENTATION_STATUS.md` ledger's own rule):**
`VERIFIED` means a command was actually run in the current session/turn and
its output was read — never assigned because "the code exists." Every
`VERIFIED` line in this file must be followed by the exact command and the
real number/result it produced.

**Rule:** no answer-key signals, ever. No item in this ledger may be marked
done on the strength of a detector that reads `FLAW` comments, filenames,
case ids, method names, or bench-shape heuristics. See the PRD's own
Section 1 for the full integrity rules — they bind every entry below.

---

## How to read this file

Each workstream (W0-W6) lists its concrete tasks. A task is `VERIFIED` only
once its own acceptance evidence (a real command + real output) is recorded
inline. Milestones (M1-M3) are separate gates run on `--split test`, at most
once per milestone, by the harness — see the PRD Section 6.

---

## W0 — Measurement integrity

| # | Task | Status |
|---|---|---|
| W0.1 | Truncation fail-closed in `bench-realworld.js` + `score-php.mjs` | NOT_STARTED |
| W0.2 | `scannedFiles`/`expectedFiles` added to `results[0]` | NOT_STARTED |
| W0.3 | Batch corpus scanning per-CWE-dir / fixed-size, merge via `merge-results.mjs` | NOT_STARTED |
| W0.4 | Scan surface = gold surface (exclude unscored CWE dirs from scan for scoring) | NOT_STARTED |
| W0.5 | Performance profiling pass (index-based catalog matching for every match.type) | NOT_STARTED |
| W0.6 | Per-CWE key hygiene self-test (no tp=fp=fn=0 rows) | NOT_STARTED |
| W0.7 | Variant-class breakdown in `macro-score.mjs` report | NOT_STARTED |

**W0 acceptance:** full dev run per language completes with zero truncation,
report shows per-variant recall, reported P/R match a hand-checked 100-entry
sample. Status: NOT_STARTED.

## W1 — Structural class resolution

| # | Task | Status |
|---|---|---|
| W1.1 | `ir.classes` emission for PHP/Python/Ruby/Go/Kotlin parsers (Java/C#/Rust already emit it) | NOT_STARTED |
| W1.2 | `callgraph.js` `classMethods` from structural class facts, not `[A-Z]` regex | NOT_STARTED |
| W1.3 | `class-hierarchy.js` `methodOwners`/`typeOfVar` from structural facts | NOT_STARTED |
| W1.4 | `dataflow/engine.js` `_resolveMemberCalleeViaCHA` handles flat dotted-string callees | NOT_STARTED |
| W1.5 | Scrambled-name regression suite for every session-landed field/collection/dispatch fix | NOT_STARTED |

**W1 acceptance:** on dev, Java variants 41/42/45/51-54/61-68/81 each move
from current 0-28% recall to >=60%, measured by the W0 variant report; C#
equivalents likewise; holdout and cve-replay gates unchanged. Status: NOT_STARTED.

## W2 — Interprocedural completeness

| # | Task | Status |
|---|---|---|
| W2.1 | Control-flow gating: constant-fold static/instance final fields + trivially-constant helper returns | NOT_STARTED |
| W2.2 | Multi-file field/chain taint (51-54, 61, 66-68) depth-aware fixed point | NOT_STARTED |
| W2.3 | Collection element taint verification (71-74) — typed reads, for-each binding | NOT_STARTED |
| W2.4 | Return-value/parameter variants (41, 42, 61, 62) under scrambled names | NOT_STARTED |
| W2.5 | Abstract/interface dispatch via declared base when receiver is a parameter (81, 82) | NOT_STARTED |

**W2 acceptance:** no flow-variant class below 70% recall on dev for Java and
C#. Status: NOT_STARTED. Blocked on W1.

## W3 — Precision: taint authority and validation guards

| # | Task | Status |
|---|---|---|
| W3.1 | Taint-authority rule: regex/structural taint-family findings defer to the taint engine where it ran | NOT_STARTED |
| W3.2 | Guard-predicate narrowing (branch-scoped taint removal after a validating predicate) | NOT_STARTED |
| W3.3 | Proven-clean ledger + `--include-proven-clean` flag | NOT_STARTED |
| W3.4 | PHP FP-by-sanitizer gated metric (<10% unattributed) | NOT_STARTED |

**W3 acceptance:** dev precision >=85% Java, >=75% C#/PHP; mutation gate
grown by >=15 guard/parameterization cases; holdout precision unchanged or
better. Status: NOT_STARTED. Blocked on W1/W2 (needs real recall to measure
precision against).

## W4 — Per-CWE coverage sweep

| # | Task | Status |
|---|---|---|
| W4.J1 | Java CWE-113 header/cookie injection | NOT_STARTED |
| W4.J2 | Java CWE-36/23 file constructors | NOT_STARTED |
| W4.J3 | Java CWE-643 XPath | NOT_STARTED |
| W4.J4 | Java CWE-80/81/83 servlet writer XSS | NOT_STARTED |
| W4.J5 | Java CWE-601, CWE-470, CWE-134 | NOT_STARTED |
| W4.J6 | Java CWE-90 LDAP re-measure (family key already fixed this session) | NOT_STARTED |
| W4.J7 | Java crypto families 319/321/325/327/328/329/330/338 | NOT_STARTED |
| W4.C1 | C# CWE-113, CWE-80/81/83 | NOT_STARTED |
| W4.C2 | C# CWE-89 remaining sinks (SqlDataAdapter etc, already partially landed) | NOT_STARTED |
| W4.C3 | C# CWE-36/23, CWE-643, CWE-470, CWE-134, CWE-601, CWE-78, CWE-90 | NOT_STARTED |
| W4.C4 | C# CWE-313/314/315 cleartext storage | NOT_STARTED |
| W4.C5 | C# CWE-523/539 cookie/transport, CWE-259/321/256/261 credentials | NOT_STARTED |
| W4.Q | Structural/quality CWE triage (decide honest-detector vs exclude-from-scan-surface per family) | NOT_STARTED |

**W4 acceptance:** no scored CWE with support >=20 below 50% F1 on dev.
Status: NOT_STARTED. Blocked on W1/W2/W3.

## W5 — PHP-specific

| # | Task | Status |
|---|---|---|
| W5.1 | Sources: nested fgets/fopen, fread, file_get_contents, shell output, unserialize, $_SERVER, class getters | NOT_STARTED |
| W5.2 | Sinks: ldap_search/list (CWE-90), ->xpath()/DOMXPath (CWE-91), include/require scoring (CWE-98), eval family (CWE-95) | NOT_STARTED |
| W5.3 | CWE-862 detector design (post-W3, needs guard-predicate distinction) | NOT_STARTED |
| W5.4 | Guard matrix (sanitizer x sink x quote-context) test file + FP triage | NOT_STARTED |

**W5 acceptance:** PHP dev macro-F1 >=75% before the milestone test run.
Status: NOT_STARTED. Blocked on W3.

## W6 — Rust (out of SARD scope, tracked for honesty only)

No SARD/Juliet suite exists for Rust. Measured via `bench:cve-replay` and
`bench:layer-recall` only. Nothing in this ledger claims a Rust F1.

---

## Milestone gates (TEST split, run once each, by the harness)

| Gate | Java target | C# target | PHP target | Status |
|---|---|---|---|---|
| M1 (after W0+W1) | >=45 | >=25 | >=25 | NOT_STARTED |
| M2 (after W2+W3) | >=65 | >=50 | >=50 | NOT_STARTED |
| M3 (after W4+W5) | >=80 | >=80 | >=80 | NOT_STARTED |

---

## Baseline (measured 2026-09-14, dev split, commit 4ce6c09e)

Command: `node test/benchmark/realworld/bench-realworld.js --app sard-juliet-{java,csharp}-strict --blind --scramble-identifiers --deep --split dev --json | node ../bench/sard/scripts/macro-score.mjs` (PHP: `node ../bench/sard/scripts/score-php.mjs --deep --split dev --json | node ../bench/sard/scripts/macro-score.mjs`)

| Language | macro-F1 | micro-F1 | P | R |
|---|---|---|---|---|
| Java | 33.5% | 50.3% | 71.7% | 38.8% |
| C# | 15.1% | 17.1% | 39.9% | 10.9% |
| PHP | 21.2% | 17.2% | 24.2% | 13.4% |

## Session log

### 2026-09-14 — loop started

- Ledger created. Status dashboard published (see repo README or ask for the
  URL — recorded in the loop's own session notes, not duplicated here since
  URLs are not durable ledger content).
- Beginning W0.1 (truncation fail-closed).
