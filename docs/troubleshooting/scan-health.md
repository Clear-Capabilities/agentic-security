# Troubleshooting: why did my scan fail?

"Failed" here covers two different questions people actually ask: *why
does `scanHealth.status` say `'partial'` instead of `'complete'`*, and
*why didn't my fix come back fully verified*. Both are covered below, using
only real, source-confirmed causes — nothing speculative. For what
`scanHealth` actually looks like and means, read
[Scan health](../walkthroughs/scan-health.md) first; this page is the
action-oriented companion.

If you got here from `ci --assurance strict`'s `assurance gate FAILED`
message, see [CI setup](../guides/ci-setup.md#security-gate-failure-vs-assurance-failure)
for the distinction between a *security-gate* failure (real findings at
your `--fail-on` threshold) and an *assurance-gate* failure (the analysis
itself didn't finish) — this page is about the second kind.

---

## Analyzer timeout

**What happened.** One or more files exceeded the per-file analysis
timeout (`AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS`, default 10 seconds). The
FR-202 preemptive kill terminates the *whole* per-file cascade for that
file, not one analyzer — so every analyzer that would have run on that file
is marked `timed_out`, not `completed`.

**Why it matters.** A killed file has no completion information for *any*
analyzer that would have run on it — reporting some of them as `completed`
would fabricate certainty the kill destroyed. `scanHealth.status` becomes
`'partial'` and `conditions[]` names the file count:
`"N file(s) exceeded the per-file analysis timeout"`.

**How to investigate.** Check `scanHealth.files.timedOut` and
`scanHealth.analyzers.timedOut` in `scan . --format json`'s output. A large
generated file, a pathological regex-prone pattern, or a very large single
function are the usual culprits.

**How to fix.** Raise the per-file budget with
`AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS` (milliseconds) for a re-run, or
exclude the offending file/path if it's generated/vendored content you
don't need scanned.

---

## Stale EPSS / KEV / calibration feed

**What happened.** One of three freshness signals in `scanHealth.freshness`
tripped its staleness threshold. KEV and EPSS are both live-fetched caches
(24-hour refresh TTL, marked `stale` past 7 days old); calibration is a
maintainer-shipped seed file (`calibration.js`'s `calibration-seed.json`,
marked `stale` past 180 days old). This is real and demonstrated: the
captured example in [Scan health](../walkthroughs/scan-health.md) shows a
scan with 120/120 analyzers clean, `status: 'partial'` driven entirely by
`freshness.epss.stale: true` at 20699 days old.

**Why it matters.** KEV membership and EPSS exploit-probability escalate
severity and risk-dollars estimates. A stale KEV catalog silently omits
recently-added CVEs (understating risk); a stale EPSS score no longer
reflects the current exploitation landscape (can err in either direction).
A structurally perfect scan (nothing crashed, nothing timed out) can still
be `'partial'` because the *data it reasoned with* is old — a different
problem from a crashing analyzer, with a different fix.

**How to investigate.** Read `scanHealth.freshness.kev` /
`.epss` / `.calibration` — each carries `ageDays` and `stale`. `conditions[0]`
names whichever one tripped.

**How to fix.** For KEV/EPSS: make sure `AGENTIC_SECURITY_OFFLINE` isn't
set and the scan has network access — the next scan re-fetches once the
24-hour TTL has passed (a fetch failure falls back to the existing cache
rather than blocking the scan, so a persistently stale cache usually means
persistently no network, not a code problem). For calibration: the seed
ships with the scanner release itself — upgrade to a newer release rather
than trying to regenerate it locally.

---

## Parser unavailable

**What happened.** The Python deep-analysis path prefers a real CST parser
(`parser-py-cst.js`, via a `python3` subprocess) but falls back to a
hand-rolled regex parser (`parser-py.js`) when that path isn't usable:
`python3`/`python` not on `PATH`, Python version below 3.8, the helper
subprocess timing out, its stdin JSON getting corrupted, or its output not
being parseable JSON.

**Why it matters.** The regex fallback does not emit `fn.calls` at all —
Python loses cross-function (interprocedural) taint tracking for that run.
The scan still produces findings; it just can't trace taint across function
boundaries in Python files for that run.

**How to investigate.** Every fallback calls `noteParserDegradation(reason)`,
readable via `pythonParserDegradation()`. Set
`AGENTIC_SECURITY_PY_PARSER_DEBUG=1` to see the underlying failure on
stderr when the helper crashes mid-batch.

**How to fix.** Install a `python3` on `PATH` at 3.8 or newer, or raise the
batch/probe timeouts (`AGENTIC_SECURITY_PY_BATCH_TIMEOUT_MS`,
`AGENTIC_SECURITY_PY_PROBE_TIMEOUT_MS`) if the helper is timing out under
load rather than genuinely missing. `AGENTIC_SECURITY_PY_PARSER=cst` forces
the CST path and errors loudly if `python3` is missing, instead of silently
degrading — useful for confirming which case you're in.

---

## Unsupported language

**What happened.** Deep/taint analysis (the IR layer) only walks languages
it has a parser for — JS/TS, Python, Java, Go, Ruby, PHP, C#, Kotlin, C++,
Rust, Swift, Dart, and Solidity, per `scanner/src/ir/CLAUDE.md`'s parser
table. A file in a format the taint engine cannot walk at all — JSON,
Terraform — correctly contributes zero taint findings; that's a scoping
fact, not a defect, because neither is "code" in the sense the taint engine
operates on.

**Why it matters.** This is easy to misread as a coverage gap when it
isn't one: Terraform still gets dedicated pattern-based IaC analysis
(`scanTerraform`/`scanIaC`, wired through the normal detector cascade like
every other analyzer) — it's specifically the *taint engine* that has
nothing to walk there, not the scanner as a whole.

**How to investigate.** `bench/layer-recall` (see root `CLAUDE.md`) tracks
per-language taint recall; a language at 0% there because it genuinely has
no IR parser is expected, not a bug to file.

**How to fix.** Nothing to fix for a genuinely unsupported format — pattern
and structural detectors still cover it. If a *supported* language's files
are producing no taint findings, that's a different, real gap; see
[Scan health](../walkthroughs/scan-health.md) and the layer-recall metrics
in `docs/METRICS.md` for whether that's expected.

---

## Deep analysis unavailable

**What happened.** The two commands default differently, and mixing them up
is the single most common way to be surprised here. `agentic-security scan`
turns deep mode **on by default outside a detected CI environment**
(`bin/agentic-security.js` sets `AGENTIC_SECURITY_DEEP=1` itself unless
`--no-deep`/`AGENTIC_SECURITY_DEEP=0` was passed) — so for a plain local
`scan`, deep mode being unavailable means it was explicitly disabled, or it
crashed. `agentic-security ci` never sets that env var itself and does not parse a
`--deep` flag of its own — deep mode stays off there unless you set
`AGENTIC_SECURITY_DEEP=1` in the environment yourself before running `ci`.

On top of that, **both** commands auto-disable deep mode inside a
detected CI environment (`CI`/`GITHUB_ACTIONS`/`GITLAB_CI`/`BUILDKITE`/
`CIRCLECI`/`JENKINS_URL`) unless `AGENTIC_SECURITY_DEEP_IN_CI=1` is also
set. `scanHealth.deepAnalysis.reason` names exactly which case applies:
`'not requested'` (never asked for, not in CI — the `ci`-command default),
`'not requested (deep analysis defaults to off in CI)'`, `'requested, but
running in CI without AGENTIC_SECURITY_DEEP_IN_CI=1'`, or (when it was
requested, enabled, and threw) `deepStatus.failure` carrying the caught
exception message while the scan falls back to pattern-only results for
that run.

**Why it matters.** Deep mode is what powers interprocedural (IR-taint)
analysis. When it's off or falls back, the scan still runs and still
produces pattern-based findings — but taint-only detections for that run
won't fire, which `scanHealth.conditions[]` states explicitly rather than
letting the gap look like a clean scan.

**How to investigate.** Read `scanHealth.deepAnalysis.{requested,enabled,
inCi,reason,failure}`. A non-null `failure` means it crashed; a null
`failure` with `enabled: false` means it was never turned on for this run.

**How to fix.** For `scan`, pass `--deep` (or set `AGENTIC_SECURITY_DEEP=1`)
to request it explicitly; for `ci`, set `AGENTIC_SECURITY_DEEP=1` in the
environment (no `--deep` flag exists there). In a detected CI environment,
also set `AGENTIC_SECURITY_DEEP_IN_CI=1`, since both commands auto-disable
deep mode there regardless of the request. If it's crashing, raise
`AGENTIC_SECURITY_DEEP_TIMEOUT_MS` (default 5 minutes) if the failure is
budget exhaustion, or investigate the specific `deepStatus.failure` message
— deep mode is best-effort by design, so a parser blowup on one file
degrades to pattern-only results rather than aborting the whole scan.

---

## Egress denied

**What happened.** An outbound call to an LLM provider (Layer-3 validation,
discovery, adversary-agent, flow-narration, or the SCA function extractor)
was evaluated by `egress/policy.js`'s `evaluateEgress()` and denied —
`.agentic-security/egress-policy.yml`'s `mode: deny` or `mode: local-only`
against a non-loopback endpoint, or the blunt
`AGENTIC_SECURITY_EGRESS_DENY=1` kill switch. This is real and demonstrated
in [Model egress](../walkthroughs/model-egress.md).

**Why it matters.** The decision runs *before* a prompt is even built — a
denied call never gets to `renderPrompt`. The affected finding is tagged
`llmValidationStatus: 'policy-blocked'` (distinct from `'model-disabled'`,
meaning nothing was configured at all) rather than silently dropped, and
the denial is written to the hash-chained
`.agentic-security/egress-audit.log` — never the prompt or code content
itself, only the outcome and reason.

**How to investigate.** Read `.agentic-security/egress-audit.log`, not the
scan's own exit code — a denied LLM call doesn't fail the scan. Each line
carries `outcome`, `reason`, `provider`, and `purpose`.

**How to fix.** If the denial is intentional policy, nothing to fix — this
is the control working. If not: adjust `mode` in
`.agentic-security/egress-policy.yml`, add the provider to
`allowedProviders`, or unset `AGENTIC_SECURITY_EGRESS_DENY`. See
[Model egress](../walkthroughs/model-egress.md) for the full three-mode
picture and the four-pass redaction pipeline that runs on anything that
*is* allowed through.

---

## Required tests unavailable

**What happened.** This one is about `fix --apply`'s verification, not
`scan` itself: `posture/test-runner.js`'s `detectTestCommand` looks for a
real (non-placeholder) `scripts.test` in `package.json` or an equivalent
language marker, and finds none. `fix-verify-loop.js` then returns
`'untested-but-passes'` instead of `'verified-clean'`, with `reason:
'no-test-command-detected'`.

**Why it matters.** `'untested-but-passes'` is a real, intentional verdict,
not a degraded form of `'verified-clean'` — it's honest about what wasn't
checked (the re-scan and lint legs still ran and passed) rather than
silently treating "nothing to test" as "tested." `fix-verify.js`'s
`degradedLegs[]` names exactly which leg was skipped, so a caller never
presents a degraded pass as a full one.

**How to investigate.** Read the `fix --apply` CLI's `verified:` line —
`"yes, but NOT fully verified"` names what was skipped — or the MCP
`verify_fix` tool's `summary`, whose `NOTE:` line carries the same
information.

**How to fix.** Add a real test command to your project (e.g.
`package.json`'s `scripts.test`) if you want the tests leg of the closed
loop (`fix-verify-loop.js`) to actually run and produce `'verified-clean'`
instead of `'untested-but-passes'`. This is independent of the
[`FULL`/`MITIGATION`/`WORKAROUND` completeness tier](../reference/glossary.md#fullmitigationworkaround):
that tier's `testDiscriminates` signal is self-reported by whatever caller
invokes fix verification (e.g. via the MCP `apply_fix`/`verify_fix` tools),
not derived from the project's own detected test command — a missing
project test runner does not, by itself, cap the tier. See
[Verified remediation](../walkthroughs/verified-remediation.md) for the
full three-vocabulary picture.

---

## Go deeper

- [Scan health](../walkthroughs/scan-health.md) — the full `scanHealth`
  shape, the real EPSS-staleness example, and fault isolation (one
  analyzer failing never aborts the whole scan).
- [Model egress](../walkthroughs/model-egress.md) — the full egress-policy
  and redaction picture.
- [CI setup](../guides/ci-setup.md) — the security-gate-failure vs.
  assurance-failure distinction, and the full CI workflow.
- [Output schema](../reference/output-schema.md) and
  [Glossary](../reference/glossary.md) — the field names and vocabulary
  used throughout this page.
