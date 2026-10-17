# Shared parsing and preprocessing (E6-03)

This records what was measured before anything was changed, what was changed because of it, and what the change achieved. The measured effect is small. The task said not to rewrite without benchmarks; the benchmarks say a rewrite would not pay.

## Where a deep scan spends its time

Profiled with `node --cpu-prof` and the scan's own stage telemetry, deep scan of 48 JavaScript files (`scanner/src/dataflow`), on an 8-core arm64 Mac that was also running other work. Total profile time 3071 ms.

| Stage (scan telemetry) | ms | Share |
|---|---|---|
| per-file detectors (121 wrapped detectors) | 893 | 37% |
| deep analysis, including building the IR | 691 | 29% |
| cross-file linking | 225 | 9% |
| each remaining stage | under 50 | under 2% each |

Inside the detectors no single one dominates: the 25 slowest reported account for 472 ms, the largest at 49 ms. The self-time profile names two functions that are shared work repeated by many detectors:

| Function | Self time | Share |
|---|---|---|
| `blankComments` (sast/_comment-strip.js) | 183 ms | 6.0% |
| `stripNoiseAndStrings` (engine.js) | 110 ms | 3.6% |
| `blank` (inside `blankComments`) | 38 ms | 1.2% |

`blankComments` is a pure function of the file text and the language. The engine asks for it about fifteen times per file, and about 90 call sites across the detectors call it directly. `stripNoiseAndStrings` is the same kind of function with six call sites. Neither result was shared.

## How many times a file is parsed

Counted by wrapping the two JavaScript parse entry points in a copy of the source:

| Parse | Calls | Distinct files | Time | Share of scan |
|---|---|---|---|---|
| IR parse (`parseJsFile`, Babel) | 48 | 48 | 176 to 199 ms | about 8% |
| module-resolver parse (`parseJs`, Babel) | 48 | 48 | 41 to 42 ms | 1.8% |

Every JavaScript file is parsed twice, once for the IR and once more by the module resolver added for E2-02, which only needs the import and export statements. Sharing the parse would remove at most the second row: under 2% of a deep scan. That does not justify coupling the resolver to the IR's internals, so it was not done. If the resolver's cost grows (for example because it starts resolving more constructs), the place to share is the resolver reading the facts the IR already extracts.

## What was changed

`util/string-memo.js`: a bounded, versioned memo for pure functions of `(text, tag)`. At most 64 entries and 24 million retained characters, least recently used out first, a text longer than a quarter of the character budget is never cached, and `AGENTIC_SECURITY_NO_STRING_MEMO=1` switches it off. It wraps `blankComments` and `stripNoiseAndStrings`. Nothing else was changed: no detector was touched, and no per-detector capability declaration was added, because the profile shows no detector whose skipping would save a measurable share.

## What it achieved

`npm run ee:parse-reuse` runs the same deep scan with the memo on and off, alternating, and writes `docs/engineering-excellence/data/parse-reuse.json`. Corpus: `scanner/src/sast`, 122 files, 1.33 million characters. Five runs per arm after a warm-up of each.

| | Memo on | Memo off |
|---|---|---|
| CPU ms (median, min to max) | 3413 (3072 to 3517) | 3430 (3331 to 3861) |
| Wall ms (median, min to max) | 2935 (2831 to 3009) | 3154 (3037 to 3320) |

- Comment-blanking calls: 4524, of which 3543 were served from the memo and 981 computed, so 78% of the repeated work is gone.
- Wall time fell 6.9% and CPU time 0.5% at the medians. A previous three-run measurement on the same machine gave 10% and 4.9%. The spread between runs is as large as the effect on CPU, so the honest summary is: a small improvement, between about 0.5% and 10%, not a multiple.
- Memory: the memo retained 1.23 million characters at the end of the run (about 2.5 MB of text), bounded at 24 million by construction. The process high-water mark was 732 MB across both arms; it is not separated per arm, so no per-arm memory delta is claimed.
- Findings: the canonical findings digest (`pipeline/canonical-output.js`) is identical with the memo on and off in the measurement and in `e6-03-shared-preprocessing.test.js` over three fixture groups (eight fixture directories), and the memoized function equals the direct one over 3000 random inputs in every language mode.

## Tradeoffs and what remains

- The warm-incremental target of 2x (E6-08) is not met by this change and could not be: preprocessing is a tenth of the work. Larger gains need incremental analysis (E6-04), which skips unchanged files entirely.
- The memo helps most where one file is visited by many detectors in a row; it is bounded so that a scan of thousands of files cannot grow it.
- The measurement was taken while another long job was running on the machine. The alternating order and medians reduce that influence; they do not remove it. Re-run on an idle machine before quoting a figure externally.
- Only JavaScript parse counts were measured. Python (a subprocess), Java and the tree-sitter languages were not profiled for repeated parsing.
