# Walkthrough: verified remediation

**Goal:** know what "verified" actually means when a fix comes back —
there are three separate, differently-cased vocabularies in this codebase,
and none of them is a single unified enum. Confusing them means trusting a
claim that was never made.

---

## Run It

The three vocabularies below come from **fix verification**
(`posture/fix-verify.js` and friends), which runs as part of
`agentic-security fix --apply`, the MCP `apply_fix`/`verify_fix` tools, and
`autopilot` — not from `agentic-security verify`, which is a different
feature entirely (the agentic verifier's `verifier_verdict` on findings
themselves, unrelated to fix output).

```bash
agentic-security fix --finding <finding-id> --apply
```

The plain CLI condenses the result to one line (see below). The full
leg-by-leg detail — the multi-line `summary` this walkthrough is mostly
about — is always computed internally, and is what the MCP `verify_fix`
tool returns verbatim to an agent caller (`{ ok, rescan, lint, tests,
honesty, poc, summary }`).

---

## Three vocabularies, not one

**1. `fix-verify-loop.js` (`verifyFixWithTests`) — the closed loop: scan +
lint + tests.** Kebab-case, three values:

- `'verified-clean'` — re-scan, lint, and tests all passed.
- `'verification-failed'` — one of those legs failed.
- `'untested-but-passes'` — re-scan and lint passed, but no test runner was
  detected in the project. This is a real, intentional verdict, not a
  degraded form of `'verified-clean'` — it's honest about what wasn't
  checked rather than silently treating "nothing to test" as "tested."

The summary line has a fixed shape, `` `${verdict} (scan: pass · lint:
skip · tests: pass)` `` — one `pass`/`fail`/`skip` per leg.

**2. `fix-verify.js` (`verifyFix`) — the richer object underneath.** This is
what the loop above actually calls first. It returns:

```
{ ok, verifiedFull, degradedLegs[], rescan: {ok, reason}, lint: {ok, runner, skipped},
  tests: {…}, honesty: {ok, tier, violations[]}, poc: {status, tier, reason}, summary }
```

- **`ok` vs. `verifiedFull` are different claims.** `ok` is "nothing that
  ran, failed." `verifiedFull` is "nothing that ran, failed, **and nothing
  was skipped**." A repo with no linter or no detected test runner can
  still reach `ok: true` — those legs don't fail-closed just because a
  small repo has no linter or test suite configured. `degradedLegs[]` names
  exactly what was skipped, so a caller can never present a degraded pass
  as a full one.
- **Real `rescan.reason` values:** `'verified'`, `'introduced-new-findings'`,
  `'original-finding-still-present'`, `'rescan-failed'`,
  `'no-files-provided'`.
- **Real `poc.status` values:** `'not-requested'`, `'still-exploitable'`,
  `'no-longer-proven'`, `'inconclusive'`. This leg re-runs the finding's
  proof-of-concept against the patched files inside the sandbox — a
  stronger claim than the re-scan, which only proves the *detector* stopped
  firing. `'inconclusive'` (the PoC couldn't run, or the sandbox couldn't
  start) is deliberately **not** counted as a pass — "couldn't prove it" is
  never treated as "fixed."

**3. `fix-honesty-gate.js` (`computeFixTier`) — the completeness tier.**
Uppercase, three values: `'FULL'`, `'MITIGATION'`, `'WORKAROUND'`. The
invariant: **`FULL` must carry no residual-risk text; anything short of
`FULL` must document one.** A rate-limit-only, docs-only, or
log-without-reject signal caps the tier at `WORKAROUND` regardless of
anything else; anything short of (sink signature changed + every caller
routed through it + a test that fails pre-fix and passes post-fix) caps it
at `MITIGATION`.

These three are separate objects answering separate questions — the
kebab-case verdict is "did the closed loop pass," the `fix-verify.js`
object is the mechanical detail behind that verdict, and the uppercase tier
is a claim about how *complete* the fix is, independent of whether it
verified clean. Don't blend them into one enum.

---

## What You'll See — the CLI's condensed line

`agentic-security fix --finding <id> --apply` prints a one-line verdict,
not the full leg-by-leg block. This is the exact `console.log` template
from `bin/agentic-security.js`'s `cmdFix`, not a captured terminal
session — the values in angle brackets vary per run:

```
✓ applied fix <historyId>  (file: app.js)
  backup: .agentic-security/fix-history/<historyId>.bak
  verified: yes — fully verified (rescan clean, no new medium+ finding, lint, tests)
  revert with: agentic-security undo
```

When a leg was skipped rather than run, the `verified:` line says so
instead of quietly claiming a full pass:

```
  verified: yes, but NOT fully verified — rescan clean, no new medium+ finding; lint: eslint not installed
```

## What You'll See — the full leg-by-leg summary

The real multi-line `summary` text `fix-verify.js` builds internally, and
what the MCP `verify_fix` tool returns to an agent caller, when every leg
passes:

```
re-scan: PASS
linter:  eslint PASS
tests:   PASS
honesty: PASS (FULL)
poc:     PASS (ran against the patch and no longer demonstrates the vulnerability)
```

If a leg was skipped rather than failed, an extra line is appended instead
of quietly passing:

```
NOTE:    PASSED, but NOT fully verified — lint: eslint not installed
```

---

## What You'll See — a rejected fix

A real fix can also come back rejected. Rather than fabricate output, this
example was **captured this session** by invoking the real
`verifyFix`/`verifyFixWithTests` functions directly against a scratch
fixture (a Node command-injection finding), passing a patch that looked
plausible — it added a comment claiming the input was sanitized — but left
the actual vulnerable call unchanged:

```js
// candidate "fix" — the interpolation into exec() is untouched
exec(`tar -czf backup.tar.gz ${filename}`, (err, stdout) => { … });
```

`verifyFixWithTests` returned:

```json
{
  "ok": false,
  "verdict": "verification-failed",
  "legs": {
    "scan": { "ok": false, "detail": { "ok": false, "reason": "introduced-new-findings" } },
    "lint": { "ok": true, "detail": { "ok": true, "runner": "none" } },
    "tests": { "ok": true, "detail": null, "skipped": true, "reason": "not-run" }
  },
  "summary": "verification-failed (scan: fail · lint: pass · tests: skip)"
}
```

The re-scan leg's real `summary` line for the same run:

```
re-scan: FAIL — introduced-new-findings
linter:  skipped (no linter config)
tests:   skipped (no-test-command-detected)
```

This example landed on `'introduced-new-findings'` rather than
`'original-finding-still-present'` — the re-scan is scoped to just the
patched file content handed to it, which in this fixture surfaced a second,
pre-existing finding the original whole-project scan hadn't isolated to
that file. Either `rescan.reason` value is real and either can produce
`'verification-failed'`; this is what the real function returned on this
input, not a cherry-picked case.

---

## What It Means

- **Three vocabularies, never one enum.** The kebab-case verdict answers
  "did the closed loop pass," the `fix-verify.js` object is the mechanical
  detail behind that verdict, and the uppercase `FULL`/`MITIGATION`/
  `WORKAROUND` tier is a separate claim about how *complete* the fix is.
  Blending them loses information each one carries alone.
- **`ok` is not `verifiedFull`.** A repo with no linter or no detected test
  runner can still return `ok: true` — those legs don't fail-closed just
  because nothing was configured to check. `degradedLegs[]` is what tells
  you a leg was skipped rather than genuinely passed.
- **The PoC leg is the strongest signal available**, because it's the only
  leg that re-executes the actual exploit against the patch — the re-scan
  leg only proves the *detector* stopped firing, which a cosmetic edit can
  achieve without closing anything.
- **A rejected fix doesn't always mean "the same bug is still there."** The
  real capture above landed on `'introduced-new-findings'`, not
  `'original-finding-still-present'` — the patch replaced one finding with
  a different (and in that case worse) one, and verification correctly
  failed it either way.
- **The honesty gate cross-checks self-reported claims against mechanical
  evidence when it exists.** A self-reported `FULL` tier is not just
  internally inconsistent when the PoC leg shows the vulnerability still
  works against the patch — `checkMechanicalTierEvidence` calls that out as
  *refuted*, a stronger claim than "the agent contradicted itself."

---

## The honesty gate's real violation messages

When `fixMeta` (an agent's self-reported residual-risk text + completeness
signals) is supplied, `gateFixOutput` checks it mechanically. Two real
violation templates:

- A banned hand-wave phrase in the residual text (`"adequately handled"`,
  `"properly validated"`, `"future work"`, `"tbd"`, `"later"`, …):
  ```
  vague-assurance phrase: "${phrase}"
  ```
- A self-reported `FULL` tier contradicted by the PoC leg actually running
  against the patch and still succeeding:
  ```
  tier 'FULL' is refuted by mechanical evidence: the proof-of-concept still demonstrates the vulnerability against the patch
  ```
  This one is asymmetric on purpose: it can only ever *add* a violation on
  real contrary evidence (the PoC leg reaching `'still-exploitable'`) — a
  missing or inconclusive PoC leg is a no-op, never treated as proof either
  way.

Plus the tier/residual invariant itself, enforced directly (not phrased as
a template): a `FULL` tier with non-empty residual text fails with `'FULL
tier cannot carry a residual'`; anything short of `FULL` with empty residual
text fails with `'non-FULL tier must document a residual'`.

---

## Try It Yourself

```bash
agentic-security fix --finding <finding-id> --apply
```

Read the `verified:` line: `yes — fully verified` means every leg that
applies to your project ran and passed; `yes, but NOT fully verified` names
what was skipped. For the full leg-by-leg detail (`re-scan`, `linter`,
`tests`, `honesty`, `poc`), call the MCP `verify_fix` tool — it returns the
same object `fix-verify.js` computes internally, `summary` included.

---

## Go Deeper

- [Finding evidence](finding-evidence.md) — the `stableId` re-scan
  verification checks for, and the fields a finding carries before you ever
  attempt a fix.
- [Scan health](scan-health.md) — the scan-level counterpart: whether the
  analysis behind a verdict actually completed.
