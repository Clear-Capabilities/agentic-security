# Engine mechanism evidence (QA-005, QA-006)

What was changed in the parser, IR and flow engine, why, how each change was chosen, and what was measured before and after.
Everything below was produced by commands run while making the change; the numbers in the tables are copied from those runs
(`measured-before-after.json` is the raw record of the development suite).

**Scope of the claims.** The labels used here are development labels written by the people who made the changes, so they show that a
change recovers the mechanism it was made for. They are not an independent population and not a sealed set, and nothing here is an
accuracy figure for real code. No sealed outcome was read or used.

## How the mechanisms were chosen

From evidence that already existed in the repository, not from a fixture ceiling: the taint-layer attribution table
(`npm run bench:layer-recall`), which lists for each corpus entry the layer that detected it, and the entries in the taint-shaped
families that were detected by a pattern layer but not by the taint layer. Each such entry was read, the missing step identified
(no source, no sink, wrong line, a suppression that should not have fired), and the same step then probed in other frameworks and
languages. A mechanism was kept only if it was real in more than one shape. No mechanism looks at a benchmark path, file name, comment,
label or expected id, and none has an environment switch: the tests rename files and identifiers and assert the same verdict.

## The mechanisms

| # | Mechanism | Layer that changed | Development example (corpus entry) | Frameworks and languages |
| --- | --- | --- | --- | --- |
| M1 | Implicit handler parameters: a controller action's or mapped method's plain string parameter is request-bound with no annotation | IR frontend and catalog sources | `CVE-2019-0980-csharp-open-redirect` | ASP.NET MVC (C#), Spring MVC (Java) |
| M2 | Request-object accessors: `$request->input()` and its siblings are sources | catalog sources | `CVE-2022-31626-laravel-sqli` | Laravel (PHP) |
| M3 | Sink argument context: `header("Location: " . $x)` is an open redirect (selected by the static prefix), and Go's redirect helpers take the target in an argument position no sink named | engine sink gate and catalog sinks | `CVE-2019-11539-php-open-redirect`, `CVE-2019-11538-go-open-redirect` | PHP, Go net/http, gin, echo |
| M4 | Go line attribution: blank lines and comments never advanced the line counter, and a blank line above `func` moved the function up | IR parser lowering | the `go-blank-lines` development case; every Go handler with a blank line or comment before its sink | Go |
| M5 | Suppression by a guard that does not dominate the sink (QA-005): a guard after the sink, in a function nobody calls, in a closed block, in a branch that only logs, a result never branched on, or a line that only defines the allow-list | engine filter | the `guard-*` development cases | JavaScript, Python, Kotlin, PHP, C# |

For each: the mechanism, adversarial semantic variants that must still be caught, benign controls that must stay quiet, and an
ablation naming the layer that causes the recovery are in `scanner/test/evaluation/engine-mechanisms.test.js` (M1 to M4) and
`scanner/test/evaluation/guard-dominance.test.js` (M5). Ablations used: remove only the IR fact and the taint layer finds nothing (M1);
the deterministic-only layer cannot supply the finding (M2, M3); the previous line arithmetic would have placed the call outside the
matching window (M4); the guard test is the only thing that changed the verdict (M5, both directions per shape).

Two related defects were fixed because the mechanisms exposed them. `_guardWindow` treated the `//` in `"https://"` as a comment start
and erased the rest of the line, which is where an allow-list check usually is; a neighbouring declaration happened to stand in for it.
And a patched C# redirect written `LocalRedirect(Url.IsLocalUrl(next) ? next : "/")` would have become a new false positive once M1 gave the
taint layer a source, so the centralized guard pass now recognizes the redirect-target guards (framework local-URL predicate, relative-path
check, host allow-list) under the same dominance rule.

## Measured: the development suite

`node scripts/dev-recovery.mjs --engine <checkout>` runs the eight development cases (each a vulnerable tree and its patched twin) through
the frozen scoring policy (end to end, line window 3) against any engine checkout. "Before" is the engine at commit `3fdf5409`, where this
work started; "after" is the engine with the work.

| | Defects recovered | Patched trees with a false positive |
| --- | ---: | ---: |
| Before | 5 / 8 | 0 / 8 |
| After | 8 / 8 | 0 / 8 |

The three recovered defects are the three guard cases (M5): each was a real finding that a guard-shaped line which did not dominate the sink
had cleared. The other five cases were already found by a pattern layer; for them the change is which layer finds them (below) and where.

## Measured: layer attribution (`npm run bench:layer-recall`, 220 corpus entries, deep mode forced)

| language | before | after |
| --- | ---: | ---: |
| c# | 12 | 13 |
| go | 13 | 14 |
| php | 13 | 15 |
| all others | unchanged | unchanged |
| **taint-detected total** | **122 / 220 (55%)** | **126 / 220 (57%)** |

No language fell. The gate compares for equality, so the baseline and `docs/METRICS.md` were updated together.

## Measured: corpus alert burden and Go line attribution

`node scripts/dev-recovery.mjs --engine <checkout> --corpus` also scans the 220 CVE-replay vulnerable trees with the deep layer and reports
the alerts a reviewer would read, the root causes they collapse to (same file, family and chained lines, window 3), and how many IR-TAINT
findings sit on a blank, brace, comment or import line, which is the signature of a mislocated finding.

| | Before | After |
| --- | ---: | ---: |
| Entries scanned | 220 | 220 |
| Raw alerts | 326 | 315 |
| Root causes | 305 | 305 |
| IR-TAINT findings | 139 | 143 |
| IR-TAINT findings on a blank, brace, comment or import line | 8 (all Go) | 0 |

The eight mislocated findings were all in Go and each duplicated a pattern-layer finding on the correct line, so they inflated the alerts a
reviewer reads without adding a root cause. With the line fixed they land on the sink they describe and deduplicate with it: 11 fewer
alerts, no fewer root causes, and four more entries seen by the taint layer.

## Gates run after the work

All run from `scanner/` on the finished work; exit codes are the real ones.

| Gate | Exit | Result |
| --- | ---: | --- |
| `npm run bench:cve-replay:check` | 0 | no drift, 220 / 220 baselined entries still pass `pre:TP post:TN` |
| `npm run bench:mutation:check` | 0 | verdict-flip correctness 35 / 35 |
| `npm run bench:layer-recall:check` | 0 | matches the baseline exactly after the deliberate `--update-baseline` (122 to 126) |
| `npm run bench:self-scan:check` | 0 after review | before the update it exited 1 with 10 files moved; every one was reviewed (below) and the baseline updated |
| `npm run test:evaluation` | 0 | 199 / 199 |
| `npm run test:dataflow` | 0 | 1455 pass, 0 fail, 2 skipped |
| `npm run test:sast` | 0 | 922 / 922 |
| `npm run test:posture` | 0 | 2790 pass, 0 fail, 16 skipped |
| `npm run test:lifecycle` | 0 | 337 / 337 |
| `npm run test:ci-parity` | 0 | 126 / 126 |
| `npm run test:smoke` | 0 | 30 / 30 |
| `npm run scorecard:check` | 0 | passes (two warnings that were already there: the bundle digest and the age of the historical independent record) |

**Self-scan review, finding by finding.** The baseline commit this work started from already failed this gate: six files had moved
(`language/nix-eval-isolation.js`, `lineage/deployment/ingest.js`, `lineage/deployment/trace-correlation.js`, `posture/evaluation/custody.js`,
`posture/evaluation/runner.js`, `posture/evaluation/scan-child.js`, eight findings in all), none of them caused by this work. They were read and
are false-positive classes the scan already carries (a regex-literal flagged for backtracking, a stored-prompt rule on a path argument, synchronous
file reads in offline tooling, a `process.env` assignment in the scan child). This work added four more, all read:

- `hooks/pre-edit-bodyguard.js` +1, `scripts/ship/run.mjs` +1. Both are the cost of M5: a rule-table line that names the cloud metadata address, and a one-line
  property lookup flagged as path traversal, were cleared before only because some guard-shaped text sat nearby. They are false positives that the old window logic hid
  by accident. They are accepted and recorded in the baseline, not suppressed.
- `posture/evaluation/dev-cases.js` +1, `posture/evaluation/release-gate.js` +1. Synchronous file reads in offline tooling, the same class as `custody.js` and `runner.js`.

Two findings that this work introduced and then removed rather than baselined: a catastrophic-backtracking flag on two regexes in `guard-dominance.js` (rewritten
without nested quantifiers and capped in length) and a path-existence check and a regex `.exec` that the scan read as a command execution in the new scripts (rewritten).

## Limits, stated plainly

- Dominance is a structural check over source text, not a control-flow graph. It recognises straight-line statements, early-exit checks, a
  value-neutralising branch, a sink inside the guarded branch and a validator helper called before the sink. Polarity of a condition is not
  judged, so a check whose TRUE branch leaves reads like a guard. Anything it cannot place is "not proven", which keeps the finding.
- The effect of M5 on precision is not free: findings that a nearby, non-dominating guard used to hide now appear. In the repository's own
  self-scan that showed as new findings on lines that are rule tables or one-line property lookups (see the self-scan review above).
- M1 covers string-shaped parameters only; a complex model parameter's field-level taint is not modelled. Kotlin Spring handlers are not covered.
- The development labels are authored by the same people who wrote the fixes. They prove a mechanism is repaired; they are not evidence about real code.
