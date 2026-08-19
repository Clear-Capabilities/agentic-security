# Independent evaluation population

**This is not the regression corpus, and the two must never be merged.**

`bench/cve-replay/` is a **regression net**: fixtures written by the same people
who write the detectors, admitted only once they score `pre:TP post:TN`, and
gated so nothing regresses. Its detection rate sits at the ceiling *by
construction*. `scripts/corpus-provenance-check.mjs` measured the consequence and
says it plainly — 199 of 201 capability entries are
`synthetic-shape-of-disclosed-cve`, so that corpus cannot support an accuracy
claim no matter how large it grows.

This directory is the other instrument: an **accuracy measurement** over code
this project did not write, labelled by people who have never seen its
detectors.

## Where the labels come from

Entries are mined from published security advisories. For each one:

- the **CWE** is assigned by the advisory database and its maintainers, not by
  us;
- the **fix commit** is the one the upstream project shipped;
- `pre/` is the package containing the changed files at the fix commit's
  **parent**, `post/` is the same scope at the **fix commit** (see "Honest
  limits" for exactly how that scope is chosen).

**Implementation files only.** A fix commit almost always touches the fix *and*
its regression test, and often a rebuilt bundle. Test files, `__tests__/`,
`.d.ts` declarations, `dist/` and `build/` output are excluded from entry
selection: the vulnerability lives in the implementation, and scoring the engine
on a spec file or a generated bundle is a guaranteed miss that looks like a
detection failure. This was measured, not assumed — before the filter, 4 of 12
entries had a test or artifact as their vulnerable file.

So a true positive means: we found the labelled weakness class in real code that
really had it, at the commit where it really existed. Nobody on this side of the
fence chose the file, the bug, or the label.

## What is measured, and how it differs from the regression corpus

| | Regression corpus | This |
|---|---|---|
| Question | did anything break? | how accurate are we? |
| Fixtures | written here | upstream code |
| Labels | written here | third-party |
| Matching | vuln title / family / CWE | **CWE only** |
| Reports | detection + correct-silence rate | precision, recall, F1 |
| Gated in CI | yes, on drift | no — a measurement, not a gate |

**Matching is CWE-only on purpose.** Scoring on this engine's own vocabulary
would grade it against words it chose itself. CWE is the one identifier the
advisory and the engine both speak.

## Scoring

Per entry, over the labelled CWE:

- **TP** — a matching finding in `pre/` (the vulnerable version)
- **FN** — no matching finding in `pre/`
- **FP** — a matching finding in `post/` (the fixed version)
- **TN** — no matching finding in `post/`

Precision `TP/(TP+FP)`, recall `TP/(TP+FN)`, F1 the harmonic mean. Every figure
carries its `{n, d}`.

**An entry that could not be fetched or scanned is UNSCORED**, excluded from
every denominator, and reported by name. It is not a miss. The precedent is
`posture/comparison.js`: an entry a participant could not run is unscored, never
counted against them, because the alternative silently penalises infrastructure
failure as if it were a detection failure.

## Measured result — 2026-08-15 (re-measured; unchanged since 2026-08-09), n=110, 0 unscored

| | Advisory-local (**the claim**) | Wide (diagnostic) |
|---|---|---|
| recall | **12.7%** (14/110) | 33.6% (37/110) |
| precision | **50.0%** (14/28) | 50.0% (37/74) |
| F1 | **0.203** | 0.402 |

By language (advisory-local): JavaScript 4/18, Python 7/57, TypeScript 3/35.

### R16: re-measured 2026-08-15 on engine 0.136.10 — identical to the 2026-08-09 result, byte-for-byte

**This includes Theme A**, not just the themes that landed most recently. `git log` puts Theme A's landing (`553f9a5`, the 9 root-cause fixes: deep-mode-everywhere, the dead-code demotion bug, sanitizer-index/kill fixes, bench-shape leak gating) at 2026-08-12 — three days *after* the 2026-08-09 baseline this RESULT.json records. Every theme in the whole PRD — Theme A (R1–R5), Theme F/R15, Theme B+D (R6/R10/R11), Theme E (R13/R14a/R14b), and Theme C (R8/R9) — landed between the baseline and this re-measurement. This re-run (fresh fetch of all 110 entries, scan state wiped before scoring, run against 0.136.10) reproduces the baseline's every number **exactly** — same TP/FP/FN/TN, same per-language split, same recall for every one of the ~40 individual CWE categories in the full breakdown. Not one of the 110 entries' scored outcomes changed, across the entire PRD.

This matters because Theme A was the plan's own hypothesized dominant lever: its milestone description states "this milestone alone may account for most of the achievable near-term recall gain, since it activates capability that already exists" (deep mode reaching every scan surface it previously didn't). §8 of the PRD names the exact contingency this triggers: *"If the independent-population re-measurement (R16) after M1 shows little movement, the diagnosis that 'deep mode being off is the dominant factor' is wrong or incomplete, and Theme B/C work should be reprioritized ahead of further Theme A polish."* That reprioritization check never happened, because the plan's own specified process — re-measure after M1, again after M2, again after M3 (see `DETECTION_GAP_REMEDIATION_PRD.md` §6) — was not followed; only one measurement was taken, at the very end, after every theme had already landed. That is itself a real process deviation, disclosed here rather than papered over: the milestone gate that was supposed to catch "Theme A isn't the lever we thought" three themes early instead only fires now, after everything shipped.

Reported plainly rather than explained away, but not a total mystery: the independent population's language distribution is JavaScript/Python/TypeScript only (0 Java, C#, Kotlin, PHP, Ruby, or Go entries in these 110). R8/R9 — "the single largest, riskiest item in the whole PRD" per its own plan — could not have moved this benchmark at all, structurally, regardless of how real the underlying fix is; the same corpus-shape mismatch R8's own status entries already document at length for `bench/layer-recall`. That still leaves Theme A, R15, R6/R10/R11/R13/R14a as work that *could* have moved a JS/TS/Python entry, and none of it did — meaning either these fixed shapes don't happen to occur in these particular 110 real-world advisories, or a fix's effect was masked by something else in the same scan (an unrelated FP suppressing the file, a sanitizer-gate demotion, reachability filtering, or one of the hard-drop/severity-mutation mechanisms Theme F's R15 targeted). This measurement cannot distinguish those cases from each other; it can only report that the net observable outcome, entry by entry, did not change across six themes of real, independently-verified fixes. Confirming which explanation applies to which entry — and whether per-milestone re-measurement earlier would have changed how this PRD was sequenced — is future work, not something this single re-run settles.

**Follow-up root-cause audit (2026-08-17):** see
[`docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`](../../docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md)
for the per-entry breakdown of all 96 false negatives from this
measurement (83 genuine deeper-engine gaps, 6 missing-catalog, 5
corpus-scoping issues, 1 not-actually-a-miss, and exactly 1 real
masked-downstream case — a `rate-limit.js` bug that had silently
discarded every finding that detector ever produced, project-wide,
since it was written), three landed fixes, and the language-coverage
mining that brought java/c#/php/go/ruby off zero (kotlin remains
unmeasurable — no admissible advisory found this pass).

**Quote the advisory-local column.** "Wide" is the same scans scored without
restricting findings to the files the fix commit touched — it asks only whether
the CWE appeared *anywhere* in the package. Over scopes holding up to 1740
findings (median 58) that is close to a lookup of "does this codebase contain
this bug class at all", a question with a much easier yes.

### Why both columns exist

Two corrections landed together: purging the engine's own scan state from the
trees before scoring (an accuracy correction — the engine had been partly
grading its own prior output) and restricting matches to the advisory's files (a
strictness correction in the *harness*). Recall fell from a previously reported
33.6% to 12.7%, and attributing that fall to the wrong cause would have been the
same reasoning error as the contamination, pointed the other way.

The decomposition settles it: **the wide figure is still 33.6%, identical to the
pre-purge number.** So the contamination, though real and worth fixing, was
**not** inflating this measurement. The entire 20.9-point drop is the benchmark
becoming honest about *where* a finding has to be.

That makes 12.7% the true recall, and it always was. It is a low number reported
as a low number — which is the point of owning the instrument rather than
tuning against it.

## Honest limits, stated up front

- **`post/` is not proof of a fix.** It is the upstream fix. A finding there is
  counted as a false positive for the labelled CWE, which is the standard
  convention, but an upstream fix can be incomplete.
- **One CWE per entry.** Real code often contains more than one weakness. A
  finding we report that is real but not the labelled CWE is invisible here —
  it is neither credited nor penalised.
- **Selection is not random.** Entries are advisories that happen to carry a
  single-repository fix commit and a CWE. That is a biased sample of all
  vulnerabilities, and the bias is towards well-maintained projects that write
  good advisories.
- **Small n is reported as small n.** Rates from a handful of entries are noise;
  the runner labels them unreliable rather than printing a confident percentage.

- **A single entry can no longer end the run.** On 2026-08-19 a full run wedged
  at entry 186 of 315 on `GHSA-hcm8-x79p-wx2w` (apache/camel, a 649 MB tree —
  the largest in the population): the process stayed alive at 0.0% CPU with no
  progress for over six hours, so it had to be killed and 129 entries were never
  scored. Reproduced on a clean checkout, so this was a pre-existing property of
  the harness: `runScan` carries a deep-mode walltime budget and a per-file
  timeout, but nothing bounded a whole-entry scan, and a block that never
  resolves is not an overrun any of them observe. There is now a per-entry
  watchdog — `AGENTIC_SECURITY_BENCH_ENTRY_TIMEOUT_MS`, default 600 000 ms —
  and a timed-out entry is **UNSCORED**, by the same doctrine as an unfetchable
  one: excluded from every denominator, reported by name, never a miss.

  It bounds the awaited promise, not the work — JS cannot cancel an in-flight
  async operation — so a wedged scan keeps its handle and the run finishes via
  the runner's explicit `process.exit` rather than hanging. A completed
  measurement that names its casualties beats an indefinite hang that names
  nothing. Worth knowing when reading any figure published before this date:
  the harness that produced it could silently stall partway through.

- **Scope is the containing package, not the whole repository.** `pre/` and
  `post/` hold the largest ancestor directory of the changed files that fits a
  400-source-file cap — in practice the package containing the fix (median 185
  files). A vulnerability whose source sits in a DIFFERENT package is still
  unreachable, so recall remains a lower bound.

  The first version held only the changed files, and that was much worse:
  materialising the package raised recall from 12.5% to 32.5% with no detector
  change at all. Whole-repo would be better still and is not free — downloading
  is cheap, scanning is not, and at a useful population size it turns the
  benchmark into something nobody runs.

- **Precision is understated in the OPPOSITE direction.** With a package-wide
  scope, an unrelated instance of the same CWE elsewhere in the package counts
  as a false positive against this advisory's label. Some FPs are therefore
  real findings that simply are not this advisory's bug.

- **The sampling frame is narrow.** Entries are advisories carrying exactly one
  repository fix commit and a CWE — a biased frame favouring well-maintained
  projects. The population is 110 entries across three languages (Python 57,
  TypeScript 35, JavaScript 18). Report the CWE and repository distribution
  alongside any rate quoted from it.

- **Benchmark trees are purged before every scan.** The engine writes
  `.agentic-security/` into whatever it scans, and those files contain CWE
  identifiers. Audited on this population: 220 polluted trees, 544 state files
  carrying `CWE-` strings — so a second scan could read the first scan's
  conclusions as source. `runner.mjs` now purges before each scan AND refuses to
  score any finding whose path lies inside a state directory; the engine also
  skips `.agentic-security/` when walking. Three independent controls, because
  this was invisible for weeks. See the Non Mutating Scan PRD (removed post-implementation).

## Running it

```bash
npm run bench:independent:mine          # add entries from public advisories
npm run bench:independent:materialise   # rebuild pre/post WITH package context
npm run bench:independent               # score and print
npm run bench:independent -- --json
```

`bench:independent:fetch` is the older changed-files-only path. It is kept
because it is fast enough for a smoke test, but **it is not the measurement** —
it understates recall by roughly 2.6× and anything quoted must come from
`materialise`.

Budget roughly 8 minutes to materialise 40 entries; scoring the full 110-entry population took ~32 minutes on the maintainer machine. The
honest measurement is an order of magnitude slower than the dishonest one, which
is why the scope is capped rather than whole-repo.

Fetched source is cached under `bench/independent/cache/` and is **gitignored**:
this repository does not vendor other people's code. The manifest pins exact
commit SHAs, so a run is reproducible as long as upstream keeps its history.
