# Walkthrough: assurance modes

**Goal:** know what `--assurance advisory|standard|strict` actually does on
`ci`, so you can tell a *severity* gate failure (real vulnerabilities) apart
from an *assurance* gate failure (the scan itself didn't finish) — and
configure `strict` deliberately rather than being surprised by it.

---

## Run It

`--assurance` is a flag on `ci` only — there is no `scan --assurance`:

```bash
npx @clear-capabilities/agentic-security-scanner ci examples/demo-app --assurance strict
```

(or the shorter `agentic-security ci examples/demo-app --assurance strict`, if
you've run `npm install -g @clear-capabilities/agentic-security-scanner` — see
the root [README's Install section](../../README.md#install))

---

## What You'll See

Real captured output, from a repo where every detector completed cleanly but
the local EPSS exploit-probability cache was stale (captured with
`agentic-security` on `PATH` after a global install — the `npx` form above
produces identical output):

```text
$ agentic-security ci examples/demo-app --assurance strict
[ci] full scan (no baseline ref detected)
[ci] 45 findings — 3 critical · 6 high · 7 medium · 17 low
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20699 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```

On a run where `scanHealth.status` comes back `'complete'`, the last line
instead reads `[ci] assurance gate PASSED (mode=strict)`.

---

## What It Means

- **Three modes, not a toggle.** `advisory`, `standard` (the default), and
  `strict`. `advisory` and `standard` are mechanically identical — neither
  ever prints an assurance-gate line, and neither can fail the build over
  scan health. Only `strict` gates, and it gates on exactly one condition:
  `scanHealth.status !== 'complete'`.
- **The `scan-health=` line is unconditional.** It prints under every
  mode — advisory, standard, and strict all surface `⚠ scan-health=partial`
  when the analysis was incomplete. What differs by mode is only whether an
  incomplete scan is also treated as a build failure.
- **`strict` is independent of `--fail-on`.** A `strict` run with *zero*
  findings can still fail the build if the scan itself didn't finish — a
  clean-looking result from a broken scan is exactly the case `strict`
  exists to catch.
- **One run, two different failure classes.** The captured output above
  shows both firing at once: `fail-on=critical  scan-exit=3` is the
  severity gate — real vulnerabilities were found at or above your
  threshold, fix them. `assurance gate FAILED (mode=strict)` is the
  assurance gate — an analyzer failed, timed out, was skipped, or (with
  provenance in play) a finding's provenance couldn't be resolved, so the
  scan can't vouch for its own completeness. They call for different next
  steps: triage findings for the first, investigate why an analyzer didn't
  finish for the second.
- **The failure-reason string names the specific `scanHealth.status`
  value** it saw (`'partial'` here), so you don't have to guess which
  analysis stage tripped it — cross-reference it against the `scanHealth`
  object itself (see [Scan health](scan-health.md)).

---

## Try It Yourself

Run all three modes against your own repo and compare:

```bash
agentic-security ci . --assurance advisory   # scan-health line only, never gates
agentic-security ci . --assurance standard   # identical behavior to advisory
agentic-security ci . --assurance strict     # gates if scanHealth.status != 'complete'
```

If your repo's scan is already complete (no stale feeds, no analyzer
failures), all three will look the same except for the trailing
`assurance gate PASSED (mode=strict)` line that only `strict` prints. To see
`strict` actually fail, run against a repo where a data feed is known to be
stale, or check `scanHealth.freshness` in `agentic-security scan . --format
json` output first to see whether your own tree would trip it.

---

## Go Deeper

- [CI setup](../guides/ci-setup.md) — where `--assurance` fits into the full
  CI-gate workflow (see its "Assurance modes" section), including the
  baseline-then-gate pattern it layers on top of.
- [Scan health](scan-health.md) — the `scanHealth` object `strict` actually
  reads, including fault isolation and the full 3-state ship verdict.
- [CLI reference](../reference/cli.md) — the complete `ci` flag list.
