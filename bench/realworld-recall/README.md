# realworld-recall — self-improving recall harness

Measures the scanner's **recall / detection-rate** against a corpus of **known,
ground-truth vulnerabilities** in external repos, and turns every miss into an
actionable, stage-attributed fix. It answers the question precision-oriented
benches can't: *of the vulnerabilities we KNOW are there, what fraction does the
scanner actually surface — and for the ones it drops, where in the pipeline did
they die?*

This is the recall counterpart to `bench/independent-eval` (per-family
precision/recall/F1 on a labeled corpus) and `bench/cve-replay` (a self-authored
`pre:TP post:TN` regression gate). Here the corpus is **known real-world vulns**
and the headline is **detection-rate**, judged **semantically**.

## What makes it different: a semantic (LLM) judge, not a string match

A real vulnerability's description ("improper neutralization of the `name`
parameter in the login query builder") almost never matches a scanner finding's
wording (`sql-injection at users.js:42`) verbatim. A string/regex match would
undercount recall badly. So the authoritative matcher is a **semantic judge**
(`judge.mjs`) that decides whether an emitted finding refers to the **same
vulnerability** by **class + location + root-cause**, not by text overlap.

- **The judge is BENCH-ONLY.** It lives entirely under `bench/` and is never
  imported by the product/scan path. It is a measurement aid, not a detector.
- **It degrades deterministically offline.** With no `AGENTIC_SECURITY_LLM_ENDPOINT`
  (and no `--endpoint`), `judgeDetection` returns `{ detected: null, reasoning:
  'no-llm-endpoint: falls back to deterministic matcher' }` — **no network call,
  never throws**. The scorer reads that sentinel and falls back to a
  deterministic matcher (same file/component location substring **AND** same
  vuln class/CWE family). So an offline run still yields a defensible, if
  conservative, recall number and is fully reproducible in CI.
- A **genuine** judge failure (endpoint set, call errored) is recorded as
  `detected: null` = **judge-error** and is **excluded from the denominator** —
  you cannot count a sample you could not adjudicate. `detectionRate =
  detected / (total − judgeErrors)`, and an unmeasured rate is reported as
  `null`, never a misleading `0` (the null-not-zero discipline shared with
  `independent-eval`).

The live HTTP call is intentionally **not wired**: `_callJudgeLLM` is a
clearly-marked stub that throws "not wired" if an endpoint is configured, so no
bench run can make a silent network call. Wire a real judge by replacing that
stub's `throw` with a `fetch` to your endpoint — the `judgeDetection` signature
stays the same.

## The self-improving half: the miss-analyzer

For every known vuln the scanner **missed**, `analyze-misses.mjs` pinpoints the
**earliest pipeline stage** that dropped it and proposes a concrete
rule/detector/prompt change. Findings flow through an ordered pipeline and a
miss is attributed to the first stage whose signal says the data never got
through:

```
recon-entrypoint → detector → taint → posture-filter → proof-gate
```

`analyzeMiss(miss, { stages })` walks the supplied ordered stage list (so the
ordering and even the stage names can evolve) and returns
`{ missId, lostAtStage, proposedFix }`. Recognised miss signals (all optional;
a bring-your-own corpus may pre-annotate them, and the runner infers what it can
from location/class overlap):

| signal | stage |
|---|---|
| `entrypointFound:false` / `fileScanned:false` / `reachedStage:'none'` | recon-entrypoint |
| `detectorFired:false` / `candidateEmitted:false` / `candidateAtLocation:false` | detector |
| `taintConnected:false` / `taintReached:false` | taint |
| `postureFiltered:true` / `suppressed:true` | posture-filter |
| `proofFailed:true` / `demotedUnreachable:true` / `unreachable:true` | proof-gate |

The result: each recall dip becomes a specific TODO ("add a detector rule for
path-traversal — the sink at `src/files/read.js:15` matched no pattern") instead
of an anonymous number.

## Cross-run history

Each non-baseline report appends a compact record (detection-rate + counts) to
`results/history.jsonl` and writes a full timestamped snapshot alongside it, so
recall can be tracked over time. `results/` is **gitignored** (local + advisory,
exactly like `bench/cve-replay/results`); the committed `baseline.json` is the
gate of record.

## Corpus format (bring your own)

`corpus/EXAMPLE.json` is a tiny **synthetic** fixture that self-exercises the
harness. **It is not a real corpus and must not be cited as a recall number.**
Bring your own with `--corpus <file.json>`. Each entry is one known
vulnerability:

```json
{
  "finding_id": "EX-001",
  "repo": "example/webapp",
  "commit": "…",
  "type": "sql-injection",
  "cwe": "CWE-89",
  "location": "src/db/users.js:42",
  "root_cause": "user-controlled req.query.name concatenated into a SQL string",
  "description": "Login lookup builds its WHERE clause by string concatenation."
}
```

Accepts `{ "entries": [ … ] }` or a bare top-level array.

## Emitted findings (three sources)

You scan the corpus repos however you like and hand the runner the findings:

- `--emitted <file.json>` — a JSON array (or `{ "findings": [ … ] }`) of the
  findings you produced. The primary bring-your-own path.
- `--scan <dir>` — run the in-repo scanner over a local checkout (copied to a
  temp dir so no scan state leaks into it).
- *(neither)* — the bundled synthetic `SMOKE_EMITTED` set, matched to
  `corpus/EXAMPLE.json`, for a fully-offline self-test.

## Run

```bash
# fully-offline self-test on the bundled synthetic corpus
node bench/realworld-recall/runner.mjs --smoke

# your corpus + your findings
node bench/realworld-recall/runner.mjs --corpus mycorpus.json --emitted findings.json

# scan a local checkout instead of supplying findings
node bench/realworld-recall/runner.mjs --corpus mycorpus.json --scan ./checkout

# machine-readable
node bench/realworld-recall/runner.mjs --smoke --json

# recall gate (exit 1 on violation) — floors detection-rate + min samples
node bench/realworld-recall/runner.mjs --smoke --gate '{"minDetectionRate":0.7,"minSamples":50}'
node bench/realworld-recall/runner.mjs --smoke --gate default

# baseline gate (same shape as bench/cve-replay + bench/router-replay)
node bench/realworld-recall/runner.mjs --smoke --update-baseline   # record per-vuln verdicts
node bench/realworld-recall/runner.mjs --smoke --check-baseline    # fail on drift
```

Run baseline operations in a **deterministic mode** (`--smoke`, or a fixed
`--emitted` file) so the gate reflects the pipeline, not judge variance.

`baseline.json` records a per-known-vuln `detected | missed | judge-error`
verdict and the gate fails the build when a previously-detected vuln regresses
to a miss, a new entry isn't detected, or a baselined entry vanishes — a newly
detected entry is allowed (recall growth) and reported as a nudge to refresh.

## Honesty / limitations

- The bundled corpus is **synthetic** and exists only to exercise the harness.
  Real recall requires a real known-vuln corpus you supply.
- Offline (no endpoint) recall uses the **deterministic** matcher, which is
  stricter than the semantic judge — it can undercount matches whose location or
  class wording diverges. Wire a judge endpoint for the intended semantic
  measurement; keep offline mode for reproducible CI gating.
- Like the other benches here, no recall number is published in this repo — run
  it locally against your own corpus.
