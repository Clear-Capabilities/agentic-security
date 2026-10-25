# Repository-wide sibling sweep: contract

<!-- seo: title="Sibling sweep contract: the result shape, the accounting rule and what it does not find" description="The fields a root-cause sweep returns, the exact-count accounting guarantee, and the limits of structural sibling matching." -->

**Maturity:** GA

After a confirmed finding, the sweep looks for other places in the repository that make the same call to the same callee, and reports them with exact counts. It runs during every scan and the result is on the scan output as `rootCauseSweep`. It is a structural match, not a proof: a sibling is a place worth looking at, never a confirmed vulnerability. Scale-stage context: [Scale](../scale/README.md).

## What qualifies

A finding drives a sweep when `confirmed === true` or its `confidenceTier` is `high`. A finding with neither is not swept. A finding whose sink snippet has a callee is matched on that callee; a finding without one falls back to its `vuln` (then `cwe`) keyword, and a finding with neither is skipped rather than invented.

## Result shape

`rootCauseSweep` is `{ sweeps, totals }`. These field tables are the contract: a compatibility test (`scanner/test/contracts/root-cause-sweep.contract.test.js`) fails when the output gains or loses a field that is not listed here, in the same commit.

**`totals`**

| Field | Meaning |
|---|---|
| `found` | Sum of `found` over all sweeps |
| `candidates` | Sum of `candidates` |
| `mitigated` | Sum of `mitigated` |

**Each entry of `sweeps`**

| Field | Meaning |
|---|---|
| `fromFindingId` | The finding that drove the sweep (`id`, else `stableId`, else `null`) |
| `sourcePattern` | The source text shown for context, or `null`. The sweep itself is driven by the sink |
| `sinkPattern` | The callee that was searched for, such as `db.query(…)` |
| `found` | Every structural match in the repository except the finding's own site |
| `candidates` | Matches nobody has looked at yet |
| `mitigated` | Matches that already carry a finding of their own |
| `remaining` | Equal to `candidates`: the number still to triage |
| `instances` | A bounded sample of the matches (at most 100) |
| `instancesTruncated` | `true` when `found` is larger than the sample |
| `language` | Present only on a Haskell sweep, which a scan adds to the same list |

**Each entry of `instances`**

| Field | Meaning |
|---|---|
| `file` | Path of the match |
| `line` | 1-based line |
| `snippet` | The trimmed source line |
| `status` | `candidate` or `mitigated-or-known` |

## Guarantees

- **Exact accounting.** `found === candidates + mitigated` for every sweep, always. The counts are accumulated exactly; only the `instances` list is bounded, and `instancesTruncated` says so.
- **The finding's own site is never reported** as its own sibling, per sweep and never globally: two findings that share a pattern each exclude only their own location.
- **Nothing is dropped.** A match that already has a finding is `mitigated-or-known`, not removed.
- **Garbage in, empty out.** Non-array findings, null entries and missing file contents produce an empty sweep, not an exception.

## What the sweep does not do

<!-- limits-verified: 2026-10-19 -->

These are measured by `bench/sibling-sweep` and gated by the `sibling-sweep-gate` release check. The corpus is small and written by the people who wrote the matcher, so the figures describe robustness over those shapes, not field recall.

- **It finds structural copies, not every sibling.** Beyond the callee, the matcher confirms how the argument is built. On the seeded sets it found every same-shape copy (159 of 159) and only 1 of 9 siblings whose argument is built another way, such as a template where the origin concatenates strings. A sweep that finds nothing does not mean there are no siblings.
- **A mention in a comment or a string can match.** The match is on a source line, so `// old: db.query(x)` can be reported. Two of the three such cases in the bench were reported.
- **It does not say a sibling is exploitable.** A candidate is a place to look. Prove it with the [exploit proof](../guides/exploit-proof-fabric.md) path or triage it like any finding.
- **A different receiver is not a sibling.** `logger.query(x)` is not `db.query(x)`. The bench's look-alike cases (different receiver, different method name, a related method on the same object) were rejected 17 of 17 times.
- **Counts are exact but the list is a sample.** Read `found` and `remaining`, not the length of `instances`.
