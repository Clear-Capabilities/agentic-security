# Eval Lab and the model router: measuring security intelligence per dollar

**Status: new. The lab itself makes no network call.** It reads a dataset, runs the arms you name, and scores what they did. A
model arm that is not local needs `--allow-external`, and the egress policy is still consulted for it before it runs.

## What problem this solves

"Which model finds the most real vulnerabilities for the money, and which one should do which job?" cannot be answered by one
lucky run or by a model's own claims. The lab answers it from measurements that a model cannot talk its way into:

* **Detection** is scored on location: right class in the right file but outside the labelled span is a miss.
* **Exploit proof** is decided by executing the arm's reproducer in the proof fabric. A reproducer that "works" on fixed code is a
  false confirmation, and it is measured, not believed.
* **Remediation** replays the original exploit against the arm's patch and runs the dataset's test command on the patched copy.
* **Cost and speed** are what the arm reported, labelled as such. Unknown cost is unknown, never zero.
* **Repeatability** comes from repeating model arms (three runs by default) and printing the spread. A mean over fewer than three
  runs is marked "not representative".

## Datasets

A dataset manifest (YAML or JSON) lists entries. Labels live in the manifest and are never written into a workspace an arm can read.

```yaml
dataset:
  id: payments-cmdi
  version: "1"
  language: javascript
  source: { kind: directory }
  split: dev                 # dev | validation | sealed
  license: MIT
  cwe: [CWE-78, CWE-89]
  leakagePolicy:
    mode: enforce            # the only accepted value
    stripComments: true
    renameFiles: true
    removePaths: ["CHANGELOG*", "docs/**"]
  test: [node, check.mjs]    # run on the patched copy for remediation scoring
entries:
  - id: ping-1
    kind: vulnerable         # vulnerable | fixed | hard-negative
    cwe: CWE-78
    workspace: { dir: cases/ping-vuln }
    expectedSpan: { file: server.js, startLine: 8, endLine: 8 }
    reproducer: cases/ping.reproducer.json     # lets the lab verify exploits and patches
  - id: hn-1
    kind: hard-negative
    category: parameterization   # sanitization | authorization | parameterization | bounds-check | correct-crypto | safe-wrapper
    resemblesCwe: CWE-89
    workspace: { dir: cases/sql-param }
    lookalikeSpan: { file: users.js, startLine: 6, endLine: 6 }
```

A real-code dataset names a fixing commit pair with `workspace: { git: { repo: ../upstream, rev: <commit> } }` (a commit id, never a
branch) and a license that permits use. Revisions are read with `git archive` from a local repository through the hardened tar
reader; nothing is fetched and no hook runs. Hard negatives are required to say what they resemble, because a negative that does
not look like a vulnerability measures nothing. A dataset with no negative entry is refused: precision cannot be measured.

## The leakage controls

Before an arm sees anything, each workspace is copied, comments are stripped with every line number preserved, files whose name
carries a weakness id are renamed, and the existing custody audit runs (answer-key file names, symlinks, protected terms, advisory
ids). A weakness id left in the content, a comment that describes the bug, or a weakness-bearing file name the policy did not
rename quarantines the entry: it is not scanned, it is named in the report, and the run is marked INCOMPLETE. Every request the lab
sends an arm is checked against the same terms first. The workspace path an arm sees contains neither the entry id nor its kind.
The result is recorded in every run as `leakageAudit`.

This is a pattern audit. It is not a proof that no paraphrase gets through, and it cannot see the prompts an arm builds inside
itself.

## Arms

An arm is the deterministic scanner, a model on a LOCAL Ollama server (`adapter: { type: ollama }`, loopback host only, through the
repository's own Ollama provider), or any other model reached through a command you supply. There is no built-in client for a
remote model: the repository's provider calls go through the feature gate, the egress policy and the audit chain, and the lab is not
a second way around them. The ollama adapter sends the neutralised workspace's source (numbered, bounded) with a JSON schema for the
task, passes the prompt through the leakage guard first, and validates the answer exactly as it validates a command arm's. Token
counts are what Ollama reports; a failed local model is never retried against another provider.

```yaml
arms:
  - id: baseline
    kind: deterministic
    tasks: [detect]
    adapter: { type: builtin-scanner, layer: deep-taint }
  - id: local-model
    kind: model
    tasks: [detect, falsify, exploit, patch]
    model: { id: qwen-coder, provider: ollama, local: true, endpoint: "http://127.0.0.1:11434" }
    adapter: { type: command, argv: [node, ./my-arm.mjs], timeoutMs: 60000 }
    price: { inputPerMTok: 0, outputPerMTok: 0 }
```

`local` is declared, never inferred, and a "local" arm that names a non-loopback endpoint is refused. The command gets its request
as a file (`AGENTIC_EVAL_REQUEST`, or `{{REQUEST}}` in `argv`), prints one JSON object on stdout, never reads stdin, and runs with a
scrubbed environment, a timeout, and cleanup of its whole process tree. Its answer is `{ "findings": [...] }` for `detect`,
`{ "verdicts": { "c1": "confirmed|refuted|uncertain" } }` for `falsify`, `{ "reproducer": {...} }` for `exploit` and
`{ "files": { "path": "new content" } }` for `patch`, plus an optional `usage` with token counts or dollars. There is no fallback
from one arm to another, so a local model can never silently become a cloud call.

## Real advisory pairs from the independent population

The lab can run on real code. `scripts/eval-lab/import-independent.mjs` turns part of `bench/independent` (published security
advisories, each with the upstream project's fix commit and the package before and after) into a dataset:

```bash
node scripts/eval-lab/import-independent.mjs --split dev --language javascript --limit 12 --out ./lab-data/js-dev
agentic-security eval run --dataset ./lab-data/js-dev/dataset.json --arms arms.yaml --tasks detect
```

Rules it enforces: only the `dev` and `validation` splits (the `sealed` split is refused outright, because exporting it into something an
arm can run on would end its sealing); only repositories whose recorded licence is on the lab's permitted list; only entries whose
before and after trees are in the local cache; and every skipped entry is listed with its reason (a licence of `NOASSERTION`, a missing
cache, a change too large to localize). Each advisory becomes a vulnerable workspace (before the fix) and a fixed workspace (after it). The
expected span is the hunk of the upstream change that removes the most old code, so an unrelated edit elsewhere in the file does not
stretch it; a fix that only adds lines gets an approximate span, marked as such. Labels stay in the manifest and out of the workspaces.

Captured on 12 advisory pairs (JavaScript, `dev` split, files the fix touched), deterministic scanner only:

```
* Scanner: 0.176.0 @ 34a22edfca36
* Dataset: independent-javascript-dev 1.0.0+2026-10-18 (dev), hash c5300b81ee948e07
* Models: none (deterministic only)
* Config: tasks detect; repeats 1; timeout 120000ms; budget none
* Machine: darwin/arm64, 8 cpus, 16 GB, node v24.20.0
* Run: 2026-10-18T22:57:12.895Z to 2026-10-18T22:57:57.524Z
* Leakage audit: clean (24/24 entries usable; comments stripped)

## detect

| arm | runs | precision | recall | f1 | macroF1 | localizationAccuracy | completion |
|---|---|---|---|---|---|---|---|
| baseline | 1 | 20.0% (not representative) | 8.3% (not representative) | 11.8% (not representative) | 14.3% (not representative) | 25.0% (not representative) | 100.0% (not representative) |
```

Read that as a baseline and as a demonstration, not as a quality claim. It is one run on 12 entries, so every figure is labelled "not
representative" by the lab itself, and it says the deterministic engine finds about one of twelve of these real advisories in a single
file with comments stripped and file names changed. That is a hard number about where detection stands on code this project did not
write, and a reason the model arms exist. `--scope package` copies the whole cached package instead of only the touched files; the
leakage audit then quarantines entries whose surrounding files (changelogs, advisories) name the vulnerability, and marks the run
INCOMPLETE rather than scoring them.

## Run one command, compare everything

```
$ agentic-security models benchmark --dataset proof/dataset.json --arms arms.json --tasks detect,falsify,exploit,patch --repeats 3 --allow-external
# Eval Lab report elab-42c84f95f549ec

* Scanner: 0.175.0 @ 6c81da148b1e
* Dataset: eval-lab-proof 1 (dev), hash 7db5057892b12659
* Models: ollama/qwen-coder (local), acme/frontier-a, bolt/budget-b
* Config: tasks detect, falsify, exploit, patch; repeats 3; timeout 120000ms; budget none
* Machine: darwin/arm64, 8 cpus, 16 GB, node v24.20.0
* Run: 2026-10-18T16:03:10.812Z to 2026-10-18T16:03:48.007Z
* Leakage audit: clean (2/2 entries usable; comments stripped)

## detect

| arm | runs | precision | recall | f1 | macroF1 | localizationAccuracy | completion |
|---|---|---|---|---|---|---|---|
| baseline | 1 | n/a | 0.0% (not representative) | 0.0% (not representative) | 0.0% (not representative) | n/a | 100.0% (not representative) |
| local-model | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% |
| external-a | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% |
| external-b | 3 | 50.0% ±0.0% | 100.0% ±0.0% | 66.7% ±0.0% | 66.7% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% |

## falsify

| arm | runs | balancedAccuracy | falseRefutationRate | falseConfirmationRate |
|---|---|---|---|---|
| local-model | 3 | 100.0% ±0.0% | 0.0% ±0.0% | 0.0% ±0.0% |
| external-a | 3 | 100.0% ±0.0% | 0.0% ±0.0% | 0.0% ±0.0% |
| external-b | 3 | 50.0% ±0.0% | 0.0% ±0.0% | 100.0% ±0.0% |

## exploit

| arm | runs | pocGenerationSuccess | reproductionRate | confirmationRate | falseConfirmationRate |
|---|---|---|---|---|---|
| local-model | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |
| external-a | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |
| external-b | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |

## patch

| arm | runs | validPatchRate | exploitBlockedRate | testPreservationRate | regressionRate |
|---|---|---|---|---|---|
| local-model | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |
| external-a | 3 | 100.0% ±0.0% | 100.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |
| external-b | 3 | 0.0% ±0.0% | 0.0% ±0.0% | 100.0% ±0.0% | 0.0% ±0.0% |

## Cost, speed and reliability

| arm | spend per run | median latency | p95 latency | timeouts | failures | unknown-cost attempts |
|---|---|---|---|---|---|---|
| baseline | no model cost | 1531ms (not representative) | 1532ms (not representative) | 0 | 0 | 0 |
| local-model | $0.0000 ±$0.0000 | 126ms ±3ms | 156ms ±35ms | 0 | 0 | 0 |
| external-a | $0.2835 ±$0.0000 | 148ms ±19ms | 212ms ±72ms | 0 | 0 | 0 |
| external-b | $0.0067 ±$0.0000 | 144ms ±18ms | 158ms ±37ms | 0 | 0 | 0 |

## Intelligence per dollar

| arm | confirmed vulnerabilities / $100 | verified fixes / $100 | true positives / $100 | recall at fixed budget |
|---|---|---|---|---|
| baseline | n/a (exploit task not run) | n/a (patch task not run) | n/a (no model cost) | 0.0% (not representative) at $10 |
| local-model | n/a (zero measured spend) | n/a (zero measured spend) | n/a (zero measured spend) | 100.0% ±0.0% at $10 |
| external-a | 352.7 | 352.7 | 352.7 | 100.0% ±0.0% at $10 |
| external-b | 15037.6 | 0.0 | 15037.6 | 100.0% ±0.0% at $10 |

## Dollars per outcome

| arm | per true positive | per confirmed exploit | per verified fix |
|---|---|---|---|
| baseline | n/a | n/a | n/a |
| local-model | $0.00 | $0.00 | $0.00 |
| external-a | $0.28 | $0.28 | $0.28 |
| external-b | $0.0067 | $0.0067 | n/a |

> At least one figure rests on fewer than three runs and is marked not representative.

Run stored: elab-42c84f95f549ec
Scoreboard updated.
(exit 0)
```

Two things to read in that output. The deterministic baseline appears only where it does the task (`detect`); it is absent from
`exploit` and `patch`, not zero. And `external-b` has the best price and the worst remediation: its patch keeps the flaw, so the
replayed exploit still succeeds and its verified-fix count is zero, whatever it reports about itself.

## Intelligence per dollar

| Figure | Meaning |
|---|---|
| Confirmed vulnerabilities per $100 | exploit-confirmed vulnerable entries (confirmed by execution) divided by measured spend, times 100 |
| Verified fixes per $100 | patches that blocked the replayed exploit and passed the tests, per $100 |
| True positives per $100 | localized detections per $100 |
| Recall at a fixed budget | process the entries in dataset order, stop when the budget is spent, and report the share of vulnerable entries found |

A figure divides by MEASURED spend only. If any attempt's cost is unknown, the figure is `n/a` and says so. A deterministic arm has
no model cost, so a per-dollar figure for it is `n/a`, not infinite, and a zero-cost local model is `n/a (zero measured spend)`.

## Route each task to the right model

`models benchmark` updates a scoreboard (`.agentic-security/eval-lab/scoreboard.json`) with each model's measured quality, median
cost and median latency per task call. The router reads it:

| Policy | Chooses |
|---|---|
| `best-quality` | the highest measured quality (ties go to the cheaper model) |
| `balanced` | the cheapest model within `--tolerance` (default 2 points) of the best |
| `lowest-cost-above-quality-threshold` | the cheapest model at or above `--threshold` |
| `local-only` | the best local model; a non-local model is never a candidate |

| Task | Measured by |
|---|---|
| `hunt` | detection F1 |
| `falsification` | balanced accuracy of confirm/refute verdicts |
| `exploit-generation` | exploit confirmation rate by execution |
| `patch-generation` | strict valid-patch rate |
| `threat-model` | nothing: there is no evaluation task, so it is never routed |

```
$ agentic-security models route explain hunt --policy balanced
Recommended: ollama/qwen-coder (local)
Detection quality: 100%
Median cost: $0.00
Median latency: 0.1s
Measured runs: 3

acme/frontier-a:
Quality: 100%
Cost: $0.04

bolt/budget-b:
Quality: 67%
Cost: $0.0009

ollama/qwen-coder selected because no cheaper model is within 2 points of its quality.

Evidence: dataset eval-lab-proof (057892b12659), 1 run record(s).
(exit 0)
```

```
$ agentic-security models route explain exploit-generation --policy local-only
Recommended: ollama/qwen-coder (local)
Exploit quality: 100%
Median cost: $0.00
Median latency: 0.1s
Measured runs: 3

ollama/qwen-coder selected because it has the highest measured quality among local models.

Not considered:
  acme/frontier-a: not a local model
  bolt/budget-b: not a local model

Evidence: dataset eval-lab-proof (057892b12659), 1 run record(s).
(exit 0)
```

```
$ agentic-security models route explain threat-model
Task: threat-model
Policy: balanced
No recommendation (no-benchmark-for-task): there is no evaluation task for threat-model, so no model has measured quality for it and none is recommended
(exit 1)
```

The router will not guess. A model with fewer than three measured runs, one whose cost is unknown under a cost-based policy, or one
the egress policy denies is excluded with the reason printed. When nothing is eligible the answer is `blocked`. Results measured on
different datasets are never compared with each other. A scoreboard or run that no longer matches its own digest is reported as
failed and is not used.

## Reports

`eval report <run-id> --format md|json|csv|html|chart [--out file]`. Every format carries the scanner version and commit, the dataset
id and hash, the model ids, the configuration, the machine profile and the timestamps, plus the leakage audit and any reason the run
is incomplete. `chart` is plain series data for plotting; `html` escapes everything it prints.

## Commands

```bash
agentic-security eval run --dataset <file> --arms <file> [--tasks detect,falsify,exploit,patch] [--repeats 3] [--concurrency 2] [--timeout 120] [--budget <usd>] [--allow-external]
agentic-security eval report <run-id> [--format md|json|csv|html|chart] [--out <file>]
agentic-security eval compare <run-id> [<other-run-id>] [--allow-different-datasets]
agentic-security eval list
agentic-security models benchmark --dataset <file> --arms <file> [same flags as eval run]
agentic-security models route explain <hunt|falsification|exploit-generation|patch-generation|threat-model> [--policy <name>] [--threshold 0.8] [--tolerance 0.02] [--min-runs 3] [--dataset-hash <hash>]
```

Exit codes: `0` done, `1` done but incomplete (leakage exclusions, a budget stop, cancellation) or no recommendation, `4` usage or
precondition. `--budget` stops starting new attempts once measured spend reaches it; the skipped attempts are recorded.

## Output schema

**Dataset manifest** (JSON or YAML; `agentic-security/eval-dataset`): `dataset` with `id`, `version`, `language`, `source.kind` (`directory` or
`git-pairs`), `split` (`dev`, `validation`, `sealed`), `license`, `cwe`, `leakagePolicy` (`mode` must be `enforce`; there is no `off`), optional
`build` and `test` argv; and `entries`, each `vulnerable` (with `cwe` and an `expectedSpan` of `file`, `startLine`, `endLine`), `fixed` (with
`resemblesCwe`) or `hard-negative` (with `category`, `resemblesCwe`, `lookalikeSpan`). A git-pairs dataset needs a licence on the permitted list.
Labels live only here; a workspace an arm can read never contains one.

**Run record** (`.agentic-security/eval-lab/runs/<run-id>.json`): the dataset hash, the scanner commit, every arm and its repeats, every
attempt with its status (`completed`, `timeout`, `error`, `blocked`, `unavailable`, `skipped-budget`), the leakage-audit result, whether the
run is `complete` and, if not, why. A run that no longer matches its own digest is reported as failed and never used for routing.

**Report** (`eval report <run-id> --format json`; also `md`, `csv`, `html`, `chart`), `agentic-security/eval-lab-report` version 1:

```json
{
  "schema": "agentic-security/eval-lab-report", "version": 1, "runId": "...", "runDigest": "...",
  "header": ["scannerCommit", "scannerVersion", "datasetId", "datasetVersion", "datasetHash", "split", "models", "config", "machine", "startedAt", "finishedAt"],
  "leakageAudit": {"status": "clean|entries-excluded|...", "...": "..."}, "complete": true, "incompleteReasons": [],
  "providerVariance": [ { "model": "...", "task": "detect", "spread": 0.0, "arms": ["..."], "representative": false } ],
  "arms": [ {
    "id": "...", "kind": "deterministic|model", "model": {}, "runs": 1,
    "tasks": { "detect": { "precision": {}, "recall": {}, "f1": {}, "macroF1": {}, "localizationAccuracy": {}, "completion": {} } },
    "economics": ["usd", "latencyMedianMs", "latencyP95Ms", "inputTokens", "outputTokens", "timeouts", "failures", "unknownCostAttempts"],
    "intelligencePerDollar": ["confirmedVulnerabilitiesPer100Usd", "verifiedFixesPer100Usd", "truePositivesPer100Usd", "recallAtBudget"],
    "dollarsPer": {}, "primary": {}
  } ],
  "notes": []
}
```

(The `header`, `economics` and `intelligencePerDollar` lines above list the real keys; in a report they are objects.) Every statistic is
`{n, unmeasured, mean, stdev, min, max, ci95, representative, note}`: `representative` is false for fewer than three runs, and an interval is
withheld when there are too few independent groups to compute one. A cost that is not reported is `null` with the reason, never `0`.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `INCOMPLETE: leakage audit: entries-excluded (N quarantined ...)` | The audit found a protected term (an advisory id, the vulnerability named in a changelog) in a workspace and quarantined that entry; the run is marked incomplete rather than scored. Use a narrower workspace scope (`--scope files` for imports) or remove the file. Do not loosen the audit. |
| Every figure says `(not representative)` | Fewer than three runs. Use `--repeats 3` or more for a model arm. A deterministic arm runs once because it is repeatable. |
| An arm's attempts are `blocked` | Either the egress policy refused a non-local model (`egress policy: ...`; pass `--allow-external` and fix the policy) or the leakage guard found a protected term in what would have been sent (`leakage guard: ...`). Nothing was sent. |
| An arm's attempts are `unavailable` | The local model server is not running, the model is not installed (`ollama-model-not-installed`), or the toolchain is missing. A run with an unavailable arm is incomplete, not zero. |
| `the ollama adapter only talks to a loopback server` | By design. Reach a remote model through the `command` adapter so the egress policy decides first. |
| `dataset.leakagePolicy.mode must be "enforce"` / `a real-code dataset needs a license that permits use` | The manifest cannot opt out of leakage controls, and a git-pairs dataset must name a permitted licence. |
| `import-independent: the sealed split is evaluated only by the sealed-label protocol` | The sealed split is never exported into something an arm can run on. Use `dev` or `validation`. |
| The import skipped entries | Each skip has a reason: licence not on the permitted list or not recorded, trees not in the local cache (`bench/independent/fetch.mjs` fills it), or a change too large to localize to a span. |
| `models route explain threat-model` says there is no benchmark | There is no evaluation task for it, so nothing is recommended. The router will not guess. |

## What is not built

* **Only a local Ollama server has a built-in adapter**, and it was tested against a stand-in that speaks the protocol, never a real
  model. A remote model attaches through the command adapter, and wrapping it so it honours the guarded model call is the operator's job.
* **The SARD corpus is not wired in, and the manifest no longer pretends it is** (the `sard` source kind was removed from the schema
  because nothing could load it). The existing SARD harness keeps its own neutralization and reads answer keys, which this lab's
  custody rules keep out of a scored run. This lab uses its own neutralizer, which is line-preserving and best effort.
* **No hand-curated corpus ships**, but the existing independent advisory population can be imported (above). Its entries are mined
  from advisories, not read and chosen one by one; the expected span comes from the fix diff, so a fix that restructures code can place it
  imprecisely. The shipped test fixtures are small and synthetic.
* **`threat-model` has no benchmark**, so no model is recommended for it.
* **Costs are what arms report.** The lab does not meter a provider; a wrapper that under-reports tokens makes a model look cheaper.
