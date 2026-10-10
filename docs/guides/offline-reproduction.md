# Offline reproduction of evaluation and routing replay

A contributor can rebuild every measuring path described in the [evaluation policy card](evaluation-policy-card.md) and the
[routing policy card](routing-policy-card.md) from what is committed, on a laptop, with no network, no model account and no
provider call. Each command below is bounded: it finishes in seconds, it reads only committed fixtures or generates its data from
a fixed seed, and it asks nothing on a terminal.

**What reproduction proves.** That the arithmetic repeats: the same inputs give the same report hash, and the controls show the
path rejects bad input. **What it does not prove.** That any population was adjudicated independently, or that any number describes
real code or a real model. Every population here is synthetic or generated and is labelled so in its output.

Run everything from `scanner/` after `npm ci --ignore-scripts`. Times are from the machine that produced the output shown
(macOS, Node 24.20.0); yours will differ. If your platform lacks a `timeout` command, the times are the bound. Where `timeout`
exists, wrapping a command as `timeout 120 npm run ...` enforces a hard stop. Linux is unverified for the execution-backed
commands, and an evaluation command that cannot run says so rather than passing.

## The recorded manifests

Reproduction starts from files that pin their inputs by hash. A changed file is refused before anything is measured.

| Manifest | What it pins | How it is checked |
|---|---|---|
| [frozen.json](../../scanner/test/fixtures/deployment-ablation/frozen.json) | each deployment-ablation source tree, deployment tree, label and the graph arm's decision rule, bound to a synthetic protocol | `npm run evaluation -- deployment-ablation` verifies the stored set against the disk first and exits 1 on a mismatch |
| [invariant benchmark manifest](../../scanner/test/fixtures/invariant-benchmark/manifest.json) and [pin](../../scanner/test/fixtures/invariant-benchmark/pin.json) | the digest of every benchmark file, and the manifest's own digest | `npm run bench:invariant-ablation -- verify` |
| [oracle conformance pins](../../scanner/test/fixtures/oracles/conformance-pins.json) | each oracle adapter's logic and fixtures | `npm run verification:conformance:static` |
| [routing pins](../../scanner/test/fixtures/routing/pre-change-pins.json) | the routing, trust, cache and advisor outputs from before routing changed | the unchanged-when-off routing test |
| synthetic protocol | three authored files, frozen with a protocol hash | `npm run evaluation:synthetic` prints the hash |
| routing replay | a generated task set, frozen by hash, replayed from recorded outcomes | `npm run reproduce:routing` prints the report, card and receipt hashes |

The hash values printed by these commands are recorded in [measurement status](measurement-status.md), and a test reruns them.

## Offline evaluation

```
npm run evaluation:synthetic
```

```text
SYNTHETIC suite: 3 authored files. These figures exercise the tooling; they are not engine accuracy.
protocol sha256:6e8477f6e0486819431fa342d584f22867174cdf6dcf25ed8b65dfa468ffae1d

layer               completed  e2e recall  e2e precision  e2e F1   conditional F1  real-code gates
deterministic-only   5/5             0.0%           0.0%     0.0%            0.0%   insufficient-population
deep-taint           5/5           100.0%          66.7%    80.0%           80.0%   insufficient-population
model-assisted       0/5             0.0%            n/a     0.0%             n/a   insufficient-population
```

Exit 0, about 4 seconds. The model-assisted layer is `unavailable` without a configured endpoint, and its five targets count as
misses rather than being dropped.

```
npm run reproduce:mini
```

```text
PUBLIC MINIATURE REPRODUCTION (offline, no sealed labels). Three authored files: figures exercise the path, not the engine.
protocol sha256:6e8477f6e0486819431fa342d584f22867174cdf6dcf25ed8b65dfa468ffae1d
engine (deep-taint): recall 100.0%, precision 66.7%, completion 100.0%; 95% interval on F1: unmeasured
real-code gates: insufficient-population

negative controls:
  ok   null-engine      null recall 0.0% vs engine 100.0%
  ok   flag-everything  flood false positives 3 vs engine 1
  ok   shuffled-labels  recall against moved labels 0.0% vs 100.0%
  ok   planted-leak     1 workspace(s) quarantined, leak gate fail
  ok   gates-need-data  real-code gates on the public suite: insufficient-population

every control behaved: the measuring path distinguishes good results from bad ones
```

Exit 0, about 3 seconds. Each negative control proves the path can fail: an engine that finds nothing scores zero, one that flags
everything is penalised, shuffled labels collapse recall, a planted answer key is quarantined, and gates refuse a tiny set.

```
npm run evaluation -- deployment-ablation
```

```text
SYNTHETIC cases authored by the tooling developers. These counts check a mechanism on constructed cases; they say nothing about benefit on real programs.
frozenHash sha256:e3e380919fc49df173101a354fe7b23a76562eb667cf167d66566a0101b80909

arm              TP  FP  FN  precision  recall
source-only       4   4   3      50.0%   57.1%
graph-enabled     7   2   0      77.8%  100.0%

paired over 14 instances (7 cases): FPs reduced 3, confirmed defects added 3, baseline confirmed defects LOST 0, FPs added 1, unchanged 7
difference (graph - source): precision 27.8% [13.6%, 50.0%], recall 42.9% [14.3%, 85.7%]  (paired-case-bootstrap, 4000 resamples)
```

Exit 0, about 3 seconds (the lines after these are runtime, coverage and the adapters validated for deployment-aware claims). The
printed `frozenHash` equals the `frozenHash` field of the committed `frozen.json`.

```
npm run bench:invariant-ablation -- verify
npm run bench:invariant-ablation -- run
```

`verify` prints `benchmark intact: v1, 15 synthetic cases, sha256:322d39bcd149ba14f38be47b01e7eccca77cb64f8735c6890a6983a2d9f0eb7f`
(exit 0, instant) and exits 1 if any benchmark file changed. `run` executes the fixtures through the trust boundary in about 12
seconds and prints three arms with Wilson intervals, for example approved contract 8/8 precision and 8/8 recall on the synthetic
fixtures. Where the boundary cannot run, every class reads `UNMEASURED`.

```
npm run verification:conformance:static
```

Exit 0 in well under a second: `verification conformance: 8 adapter(s) conform (static contract and pins only; execution was not requested)`.
The execution half is `npm run verification:conformance:check` (about 20 seconds); it reports `not-run` rather than passing on a
host that cannot execute.

## Offline routing replay

```
npm run reproduce:routing
```

The first lines it prints:

```text
Routing replay report (SYNTHETIC): unmeasured
the population is synthetic: it exercises the machinery and measures nothing about real routing

Denominators: 240 frozen task(s), 240 paired, 0 dropped, 240 paired adjudicated, 0 unadjudicated.
Replay: offline (recorded outcomes), 0 paid call(s), $0.
Quality: baseline 81.3%, proposed 77.5%, difference -0.0375, 95% interval [-0.0625, -0.0165625].
Measured cost: median baseline $0.10017, proposed $0.05008615, reduction 50.0%; retries 0 vs 0.
...
Claims:
  none. No routing advantage is claimed.
```

and, after the policy card hash, seven controls that must each print `ok`:

```text
controls:
  ok   synthetic-never-passes   a synthetic population with passing arithmetic reads 'unmeasured', claim allowed: false
  ok   gate-discriminates       meets criteria: pass; quality loss at far lower cost: fail; 120 tasks: insufficient-population
  ok   cherry-pick              removing the failed pairs after the fact: invalid
  ok   dropped-failures         failed outcomes left out of the record: invalid
  ok   unbounded-replay         a paid replay with no bounded authorization: UNBOUNDED_REPLAY, 0 call(s) made
  ok   reproducible             report hash identical on a rebuild; receipt chain chain verified
  ok   control-honoured         disabled keeps 'claude-sonnet-4-6' (mode disabled); pin gives 'pinned-model'
```

Exit 0, about half a second, zero paid calls. `--json` prints the hashes in a machine-readable form (`reportHash`, `cardHash`,
`receiptsHead`), and `--receipts <file>` writes the exported hash-linked receipt chain. To see the script can fail, break one control
on purpose:

```
npm run reproduce:routing -- --fault cherry-pick
```

This exits 1 and ends with `A CONTROL FAILED: the routing replay path cannot be trusted until this is understood`. Each other
control name works the same way.

## Reproducing a single figure from its record

1. Read the row in [measurement status](measurement-status.md) and the command beside it.
2. Run the command from `scanner/`.
3. Compare the printed hash with the recorded one. A different hash means a different input or a different tool version; it is
   not a rounding difference, because the runs are deterministic.
4. For a committed artifact (the independent record), compare its SHA-256 with the digest in the same page.

The independent record is not re-run by any command here: scoring takes about 32 minutes, needs the fetched upstream packages and
the right engine checkout, and the record is of engine 0.141.0.
