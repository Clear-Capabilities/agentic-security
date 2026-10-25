# Scan health

<!-- seo: title="Scan health: how Agentic Security refuses to fake a green result" description="scanHealth records whether every analyzer finished and whether the data was fresh, so a scan that found nothing because it did not run is never reported as clean." -->

**Maturity:** GA

A scan answers two different questions: *what did we find*, and *did the analysis that looked for it actually finish*. `scanHealth` is the record of the second one. It is the reason "zero findings" is never reported as "safe".

## What `scanHealth` records

Real captured shape, from `agentic-security scan examples/demo-app --format json`:

```json
{
  "schemaVersion": 1,
  "status": "partial",
  "files": { "expected": 6, "scanned": 6, "skipped": 0, "timedOut": 0 },
  "analyzers": { "expected": 120, "completed": 120, "failed": 0, "timedOut": 0, "skippedByPolicy": 0 },
  "deepAnalysis": { "requested": true, "enabled": true, "reason": null, "failure": null },
  "lineageAnalysis": { "requested": false, "enabled": false, "reason": "not requested", "failure": null },
  "freshness": {
    "kev": { "source": "cache-fresh", "ageDays": 0, "stale": false },
    "epss": { "source": "cache/live", "ageDays": 20745, "stale": true },
    "calibration": { "ageDays": 152, "stale": false }
  },
  "conditions": ["EPSS exploit-probability data is stale (20745 day(s) old)"]
}
```

| Field | Meaning |
|---|---|
| `status` | `complete` or `partial`. The one value a gate reads. |
| `files` | Files expected, scanned, skipped, and timed out |
| `analyzers` | Analyzers applicable to this file set, and how many completed, failed, timed out or were skipped by policy |
| `deepAnalysis`, `lineageAnalysis` | Whether the deep taint pass and the security-graph pass were requested, ran, or failed, each reported separately |
| `freshness` | Age and staleness of the exploited-vulnerability catalog, the exploit-probability data, calibration, and custom rules |
| `conditions[]` | The human-readable reasons `status` is not `complete` |

A scan can be structurally perfect (nothing crashed, nothing timed out) and still be `partial` because the data it reasoned with was stale. Those are different problems with different fixes: refresh the cache, or investigate a failing analyzer.

For Haskell and Nix, `scanHealth.languageCoverage` adds what the language analyzers could not do, as conditions, rather than dropping it. See [the walkthrough](../walkthroughs/scan-health.md#haskell-and-nix-conditions).

## Three-state verdict, not two

`toShipVerdict()` folds findings and scan health into one answer:

- **Clean and complete:** zero actionable findings *and* `scanHealth.status` is `complete`. The only state that means what "0 findings" used to be assumed to mean.
- **Scan incomplete:** zero actionable findings, but the scan is `partial`. Reported as "scan incomplete, cannot confirm safe to deploy".
- **Not safe to deploy:** actionable findings exist, regardless of scan health.

## One analyzer cannot hide another's findings

Each per-file detector call is isolated (`runDetector()` in `pipeline/detector-runner.js`). An analyzer that throws becomes one entry in `analyzers.failed`; it does not discard every other analyzer's findings for that file. The project found and fixed a real gap here during its own hardening, when two detectors were bypassing the isolating wrapper, and pinned the fix with a fault-injection test. See the [walkthrough](../walkthroughs/scan-health.md#fault-isolation-one-analyzer-failing-doesnt-abort-the-scan).

## A file skipped for size or density

A scan that skipped a file because it was too large or too dense (minified bundles, very large data files) is `partial`, where it used to read `complete`. Strict assurance mode fails such scans.

## What scan health does not tell you

<!-- limits-verified: 2026-10-19 -->

- It does not rate the code. `complete` means the analysis finished, not that the code is good.
- It does not say the analyzers found everything. Recall is measured separately; see [benchmarking methodology](benchmarking-methodology.md).
- A stale feed can only be detected relative to its own timestamp. A cache that is wrong but recent is not flagged.

## Where it shows up

- `scan --format json` has the top-level `scanHealth` key.
- `ci` prints `[ci] ⚠ scan-health=<status> ...` and, in `strict` assurance mode, fails on `partial`. See [assurance modes](assurance-modes.md).
- The ship verdict and the report headline quote `conditions[]`.
- Every Code Boundaries graph carries a `scanHealth` snapshot.

## Go deeper

- [Walkthrough: scan health](../walkthroughs/scan-health.md), field by field
- [Troubleshooting: why a scan reported partial](../troubleshooting/scan-health.md)
