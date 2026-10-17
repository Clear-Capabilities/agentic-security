# Engineering excellence: index

This directory is the evidence behind the engineering-excellence programme: what was built, how it was measured, and, in the last section, what is **not** proven. Every number on this page is captured from a result file or a command by `node scripts/engineering-excellence/doc-captures.mjs`, and `--check` fails when one drifts. The live task ledger is `STATUS.md` and `scripts/engineering-excellence/status.json`.

## Start here

| If you want | Read |
|---|---|
| How a release is judged, signed and verified | [Release assurance guide](../guides/release-assurance.md) |
| A run of the whole flow on a project you can read | [End-to-end demo](E2E_DEMO.md) (project: `examples/assurance-demo`) |
| How accurate the engine is on code it was not built from | [Baseline](BASELINE.md), [evaluation protocol](EVALUATION_PROTOCOL.md) |
| Why it missed what it missed | `bench/independent/runs/<run>/FORENSICS.md` |
| How fast it is and what it costs | [Performance](PERFORMANCE.md) |
| What the program decided and where it deviated | [Decisions](DECISIONS.md) |

## What each document establishes

| Document | Epic | Establishes |
|---|---|---|
| [Baseline](BASELINE.md), [Dataset provenance](DATASET_PROVENANCE.md), [Evaluation protocol](EVALUATION_PROTOCOL.md) | E0, E1 | The independent population, how it was frozen, and the rules for quoting a result |
| [IR contract](IR_CONTRACT.md) | E2 | What the intermediate representation models, per language, measured |
| [DCI maturity audit](DCI_MATURITY.md), [DCI on application-shaped cases](DCI_REAL_APP.md) | E4 | What the deterministic context analysis detects, and how it scored on hand-written authorization cases |
| [Runtime and deployment provenance](RUNTIME_PROVENANCE_AUDIT.md) | E5 | What ties a runtime observation to a build |
| [Parse reuse](PARSE_REUSE.md), [Analysis cache](ANALYSIS_CACHE.md), [Third-party completion](THIRD_PARTY_COMPLETION.md), [Adversarial boundaries](ADVERSARIAL_BOUNDARIES.md), [Performance](PERFORMANCE.md) | E6 | Bounded scans, why targets did not finish, and measured speed |
| [Evidence contracts](EVIDENCE_CONTRACTS.md), [Provenance coverage](PROVENANCE_COVERAGE.md), [Fix benchmark](FIX_BENCHMARK.md) | E3, E7 | What each kind of evidence must carry, who introduced a finding, and how fixes are verified |
| [End-to-end demo](E2E_DEMO.md) | E8 | The flow from scan to offline verification |

## Where things stand, captured

### Independent accuracy of the engine (E1)

This is the only figure in the programme measured on code the engine was not built from. It is low, and the forensics say why.

<!-- capture: baseline-headline -->
```text
run a72968195aa1, engine 0.172.0, 278 of 283 entries scored (5 timed out, unscored)
localized precision 6/19 = 31.6%
localized recall    6/278 = 2.2%
localized F1        0.040 (95% interval 0.013 to 0.075)
```

### Deterministic context analysis on hand-written authorization cases (E4-06)

These cases are written and labelled by the programme's author, so this is **not** accuracy on real software.

<!-- capture: dci-real-app-overall -->
```text
39 routes: TP 9, FP 2, FN 0, TN 20, unresolved 8; precision 82% (9/11), recall 100% (9/9)
```

### Performance on three project sizes (E6-08)

<!-- capture: perf-large-verdict -->
```text
small: P95 236 ms, peak RSS 218 MB, within budget
medium: P95 3002 ms, peak RSS 563 MB, within budget
large: P95 25850 ms, peak RSS 1232 MB, NOT GREEN (3 of 3 runs finished with a scan health other than complete)
```

### The end-to-end demo, step by step (E8-02)

<!-- capture: e2e-steps -->
```text
[start] copied examples/assurance-demo (10 files) to a scratch directory; offline mode on; every attempt to open a network connection is refused and counted
[scan] 9 findings (8 medium or above); scan health complete
[triage] 4 of 4 expected true positives were reported; 1 of 3 expected false positives were reported and marked by the reviewer; 3 reported finding(s) have no recorded decision
[validate] 3 candidate(s) from cross-route consistency and the tenant invariant; 3 became findings, 1 of them proven by an executed attacker request; 0 refuted. SQL injection and command injection stay taint findings: nothing was executed for them
[patch] 3 candidate patches applied to scratch copies (2 correct, 1 false fix)
[verify] 2 of 3 patches fully verified; the false fix passed the security re-analysis and the attack replay and was refused on behaviour (owner-can-update-own-note)
[sca] 2 vulnerable dependencies from the local advisory data; 1 reached by a call to the advisory's function, 1 imported but not reached
[runtime] collection is off until a policy file switches it on (first attempt: refused); after opt-in 2 records were ingested; /search is corroborated by the released build, the /notes/:id records came from an older build and corroborate nothing
[sign] release package with 10 evidence records signed with a throwaway Ed25519 key; the verdict computed from its own contents is not_deployable
[verify-offline] the independent verifier accepted the package (exit 0); a copy with one finding's severity lowered was rejected (exit 1); the stated verdict matches the one recomputed from the contents
```

## What is NOT proven

Read these before relying on anything above. They are the open items the programme itself recorded; none was waived.

- **Independent accuracy is low and was measured once.** A localized F1 near 0.04 on 278 scored entries. 272 misses are classified (151 had no detector rule fire at all). One targeted change since (a Ruby path-resolver rule) recovered one of them, measured by re-running the three entries it can reach (true positives 6 to 7, false positives unchanged); the pinned baseline was not re-run, and the sealed holdout was not used.
- **The DCI case corpus is not independent.** It is synthetic, labelled by its author, with two web stacks of which Flask is mostly unresolved (no ownership or role extraction for Python). It reports two false positives and a router-mount gap.
- **Deep taint analysis is not incremental.** The analysis cache covers the per-file detector stage only; a changed-file scan is about 1.7 times faster than a cold one, below the 2 times aspiration, and the repository's own source (829 files) stops its deep analysis early, so that class never reports a complete scan.
- **Pattern detectors flag constant operands.** A query or command built by concatenating a constant is reported at reduced confidence in JavaScript, Python and Go; the flow-based layer is correctly silent. Pinned by a test, not fixed.
- **Provenance attribution is below its 95 percent target** for the eligible findings, because project-wide detectors cannot be replayed one file at a time. The coverage and its causes are in [Provenance coverage](PROVENANCE_COVERAGE.md).
- **Several capabilities are libraries with tests, not default behaviour.** The release package, verdict, perspectives, compliance truth model, fleet ranking and runtime explanation are reachable through scripts and the `release-view` command; the default `scan` does not assemble or sign a package.
- **The demo's inputs are local data.** Its advisories, runtime records and behaviour checks were written for the demo; nothing in it was collected from a running service or a vulnerability feed.
- **The released bundle (`dist/`) is rebuilt only by the release gate**; see `STATUS.md` for whether this checkout's bundle matches its sources.
- **Merging the feature branch is not authorised** by the programme, and nothing was pushed or published.
