# Walkthrough: scan health

**Goal:** read the `scanHealth` object so you can tell a scan that found
nothing because your code is clean apart from a scan that found nothing
because part of the analysis didn't run — and know that one failing
detector never silently swallows the rest of a scan's findings.

---

## Run It

```bash
agentic-security scan . --format json
```

There is no dedicated `--explain-health` flag — that surface doesn't exist.
The real place `scanHealth` shows up is inside `scan --format json`'s
output (look for the top-level `scanHealth` key), and as `ci`'s printed
`⚠ scan-health=<status>` stderr line (see [Assurance
modes](assurance-modes.md)).

---

## What You'll See

Real captured `scanHealth`, from a scan where every one of 120 analyzers
completed with zero failures and zero timeouts — the only thing wrong was
that the local EPSS exploit-probability cache was stale:

```json
{
  "scanHealth": {
    "schemaVersion": 1,
    "status": "partial",
    "files": { "expected": 6, "scanned": 6, "skipped": 0, "timedOut": 0 },
    "analyzers": { "expected": 120, "completed": 120, "failed": 0, "timedOut": 0, "skippedByPolicy": 0 },
    "deepAnalysis": { "requested": true, "enabled": true, "inCi": false, "ciOverrideAllowed": false, "reason": null, "failure": null },
    "lineageAnalysis": { "requested": false, "enabled": false, "reason": "not requested", "failure": null },
    "annotatorErrorCount": 0,
    "freshness": {
      "kev": { "source": "cache-fresh", "ageDays": 0, "stale": false, "entries": 1694 },
      "epss": { "source": "cache/live", "ageDays": 20699, "stale": true, "cvesChecked": 8 },
      "calibration": { "ageDays": 107, "stale": false },
      "customRules": { "checked": 0, "stale": false, "staleFiles": [] }
    },
    "conditions": ["EPSS exploit-probability data is stale (20699 day(s) old)"]
  }
}
```

---

## What It Means

- **`status` is binary: `complete` or `partial`.** Every other field exists
  to explain *why* it's one or the other — `status` itself is what a gate
  (like `ci --assurance strict`) actually reads.
- **This example proves the two failure modes are genuinely separate.**
  `files` and `analyzers` are both fully clean — 6/6 files scanned, 120/120
  analyzers completed, `failed: 0`, `timedOut: 0`. `status` is still
  `'partial'`, driven entirely by `freshness.epss.stale: true`. A scan can
  be structurally perfect (nothing crashed, nothing timed out, nothing was
  skipped) and still be `partial` because the *data it reasoned with* was
  stale — those are different problems with different fixes (refresh the
  EPSS cache vs. investigate a crashing analyzer).
- **`conditions` is the human-readable reason list.** It's what both the
  `ci` stderr line and the `toShipVerdict` headline quote directly — in
  this case, `"EPSS exploit-probability data is stale (20699 day(s) old)"`,
  matching the `[ci] ⚠ scan-health=partial — EPSS exploit-probability data
  is stale (20699 day(s) old)` line from [Assurance modes](assurance-modes.md).
- **`deepAnalysis` and `lineageAnalysis` are reported separately from the
  main analyzer count**, because each has its own requested/enabled/failure
  state independent of whether the 120 core analyzers ran cleanly.

---

## Fault isolation: one analyzer failing doesn't abort the scan

`analyzers.failed` above is `0` — but what happens when a detector actually
throws? Every one of `engine.js`'s per-file detector calls is wrapped by
`runDetector()` (`scanner/src/pipeline/detector-runner.js`), whose contract
is:

> "Run one detector (`fn`), isolating any exception it throws so it cannot
> abort the caller's per-file loop. On success, returns `fn()`'s value
> unchanged. On a thrown exception, appends a structured entry to
> `detectorErrors` and returns `undefined`."

That isolation isn't just a design intent — it was found to have a real gap
and got fixed. During the assurance-hardening work, an audit of every
detector call site found two, `scanWeb3Advanced` and `scanK8sAdmission`,
that had been called directly instead of through the `runDetector` wrapper.
From the project's own decision record
(`docs/implementation/assurance-hardening-decisions.md`, D-0051):

> "the audit found `scanWeb3Advanced` and `scanK8sAdmission` were called
> directly (`_aF.push(...scanK8sAdmission(p,cc))`), not wrapped in
> `runDetector` — 2 of the 128 call sites D-0028 step (b) was supposed to
> have migrated. An exception from either would propagate out of
> `_runFileCascade` entirely, discarding every OTHER detector's results for
> that file (everything sequenced after it), a real violation of FR-201's
> own acceptance criterion."

In other words: before the fix, one of those two detectors throwing would
have silently thrown away every other detector's findings for that file —
not just its own. It was fixed by wrapping both identically to the other
126 already-isolated call sites, and proven with a dedicated fault-injection
test (`scanner/test/detector-fault-injection-k8s-admission.test.js`) that
injects a real exception and asserts the sibling detectors' findings still
come back. That's the guarantee `analyzers.failed` in `scanHealth` is
actually reporting on: a failing analyzer shows up as one entry in
`failed`, not as a hole in every other analyzer's results for that file.

---

## The payoff: a 3-state ship verdict, not 2

This is why `scanHealth` matters to more than a JSON field: it's the input
to the one-screen verdict most people actually read
(`toShipVerdict`, `scanner/src/report/index.js`):

```js
const scanIncomplete = scan.scanHealth?.status && scan.scanHealth.status !== 'complete';
const clean = actionable.length === 0 && !scanIncomplete;
```

- **`clean` → ✅ `Safe to deploy`** — zero actionable findings, and the scan
  itself completed. The only state that means what "0 findings" used to be
  assumed to mean.
- **`scanIncomplete`, zero actionable findings → ⚠️ `Scan incomplete —
  cannot confirm safe to deploy`** — exactly the EPSS-staleness example
  above: nothing actionable turned up, but the analysis didn't finish
  cleanly, so "nothing found" cannot be read as "nothing's there."
- **otherwise → ❌ `Not safe to deploy`** — actionable findings exist,
  regardless of scan health.

A scan that finds nothing is no longer automatically "safe" — it's only
safe if it also finished cleanly. That's the entire reason `scanHealth`
exists.

---

## Try It Yourself

```bash
agentic-security scan . --format json | grep -A 20 '"scanHealth"'
```

Check `status` first. If it's `partial`, read `conditions[0]` for the human
reason, then look at whichever sub-object it points to (`freshness.epss`,
`analyzers.failed`, `files.timedOut`, etc.) for the specific signal that
tripped it. If you have `jq` installed:

```bash
agentic-security scan . --format json | jq '.scanHealth'
```

---

## Go Deeper

- [Assurance modes](assurance-modes.md) — how `ci --assurance strict` gates
  on `scanHealth.status`, independent of `--fail-on`.
- [CI setup](../guides/ci-setup.md) — the "Security gate failure vs.
  assurance failure" distinction, and the full CI-gate workflow.
- [Architecture](../ARCHITECTURE.md) — where `pipeline/coverage-ledger.js`
  and `pipeline/scan-health.js` sit in the overall scan pipeline.
