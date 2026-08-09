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
- `pre/` is the changed files at the fix commit's **parent**, `post/` is the same
  files at the **fix commit**.

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

- **⚠ The trees contain only the CHANGED files, and that penalises us.** This is
  the most important limitation on this page. `pre/` and `post/` hold the files
  the fix commit touched — not the repository. An interprocedural taint engine
  needs the caller, the route registration, the sanitiser it might have passed
  through; none of that is present. A finding that requires a source in one file
  and a sink in another cannot be made here **even when the engine would find it
  on the real repository**.

  So the recall figure is a **lower bound**, and the gap between it and reality
  is unmeasured. Do not read it as "the engine finds 1 in 6 real bugs". Read it
  as "the engine finds 1 in 6 real bugs *when shown only the diff's files*".

  Fixing this means materialising whole repositories at both commits, which is
  orders of magnitude more disk and network. That is the obvious next step and
  it is deliberately not in the first version — a lower bound you can defend
  beats a better number you cannot yet produce.

- **The CWE mix is long-tail by construction.** Advisories that carry a single
  fix commit skew towards specific, well-described weaknesses — cache leakage,
  origin validation, observable discrepancy — rather than the injection classes
  a SAST engine targets first. That is a property of the sampling frame, not of
  the engine, and it is another reason the headline rate understates.

## Running it

```bash
npm run bench:independent:fetch    # materialise pre/post from upstream (network)
npm run bench:independent          # score and print
npm run bench:independent -- --json
```

Fetched source is cached under `bench/independent/cache/` and is **gitignored**:
this repository does not vendor other people's code. The manifest pins exact
commit SHAs, so a run is reproducible as long as upstream keeps its history.
