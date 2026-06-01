# Independent evaluation harness (PRD R16)

Per-family **precision / recall / F1** (+ Brier/ECE calibration) for the scanner,
measured against a **ground-truth-labeled corpus**.

## Why this exists (and how it differs from cve-replay)

`bench/cve-replay/` is a **regression gate**: we authored both the vulnerable and
the fixed sample for every entry, and it asserts `pre:TP post:TN` at F1 = 1.000.
That is necessary (it stops regressions) but **not sufficient** to claim the
scanner is *better than other tools* — you cannot grade yourself on an exam you
wrote. R16 grades the scanner against corpora **we did not author**, and reports
the metrics an auditor (or a buyer comparing tools) actually asks for, including
**recall** — which requires knowing the vulnerabilities the scanner *missed*
(false negatives). `posture/holdout-eval.js` cannot measure recall on its own
because it only sees findings that were emitted; this harness supplies FN by
scoring labeled samples the scanner produced *no* finding for.

## Status: harness built, real corpus NOT yet wired

The `corpus/` directory shipped here is a **4-sample SMOKE fixture** that exercises
the harness end-to-end. **It is not an independent corpus and must not be cited as
a quality number.** Wiring real corpora (data acquisition) is the remaining R16
work — see "Wiring a real corpus" below.

## Usage

```bash
# from scanner/
npm run eval:independent              # run against corpus/manifest.jsonl, print table
npm run eval:independent:gate         # same + apply the default gate (exit 1 on violation)

# direct, with options:
node ../bench/independent-eval/runner.mjs \
  --manifest <path/to/manifest.jsonl> \
  --root <corpus-root-dir> \
  --json out.json \
  --gate '{"aggregateF1":0.85,"perFamilyRecall":0.7,"minSamples":200}'
```

The runner scans a **temp copy** of the corpus root (comment/`node_modules`/state
excluded) so it never writes scan state into the repo. Findings are attributed
per file and scored against the manifest labels.

## Manifest format (`manifest.jsonl`)

One JSON object per line. Paths are relative to `--root` (default: the manifest's
directory).

```json
{"id":"...","path":"vulnerable/sqli.js","language":"js","cwe":"89","family":"sql-injection","label":"vulnerable"}
{"id":"...","path":"clean/sqli_safe.js","language":"js","cwe":"89","family":"sql-injection","label":"clean"}
```

| field | meaning |
|-------|---------|
| `path` | file relative to the corpus root |
| `label` | `vulnerable` (expect a matching finding) or `clean` (expect none) |
| `family` | the labeled vuln class; a finding matches if its `family` equals this |
| `cwe` | optional; a finding also matches if its CWE contains this number |
| `language` | optional; drives the per-language calibration breakdown |

Scoring per sample: vulnerable+matched → **TP**, vulnerable+unmatched → **FN**,
clean+matched → **FP**, clean+unmatched → **TN**. Per-family and aggregate
precision/recall/F1 follow. A metric that is `null` (no samples) is reported as
`—` and is treated as a **gate violation** if a threshold is set for it — you
cannot pass a bar you never measured.

## Gate

`--gate` accepts a JSON object (inline or a file path), or the literal `default`.
Supported thresholds: `aggregateF1`, `aggregatePrecision`, `aggregateRecall`,
`perFamilyF1`, `perFamilyRecall`, `minSamples`. Exit code is `1` on any violation,
`0` otherwise — wire it into CI the same way as `bench:cve-replay:check`.

## Wiring a real corpus (the remaining R16 work)

The scoring core (`score.mjs`, unit-tested in
`scanner/test/independent-eval.test.js`) and the runner are corpus-agnostic. To
make R16 a real superiority measurement, drop in independent data and point the
manifest at it:

1. **OWASP Benchmark v1.2** — `bench/owasp-benchmark-v1.2/` (regenerated; the per-
   test `expectedresults-1.2.csv` gives ground-truth true/false per test case).
   Generate a `manifest.jsonl` mapping each `BenchmarkTestNNNNN.java` →
   `{family, cwe, label}` from the CSV. Run with `AGENTIC_SECURITY_BENCH_SHAPE=0`
   (blind) so answer-key adapters can't leak labels.
2. **Harvested CVE-fix pairs** — real pre/post commit pairs from public advisories
   (not the ones we authored in cve-replay), labeled by the advisory's CWE.
3. **SARD/Juliet** — `bench/sard-juliet-java/`; folder names carry the CWE.

Until real data is wired, treat any number this harness prints as a smoke check
only. The gate thresholds in `runner.mjs#DEFAULT_THRESHOLDS` are intentionally
inert (no F1 floor) so the skeleton never asserts a quality claim it can't back.
