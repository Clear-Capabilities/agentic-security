# Verified remediation

<!-- seo: title="Verified remediation: what a verified fix actually verified" description="Verification legs, full versus degraded verification, FULL, MITIGATION and WORKAROUND completeness tiers, and how skipped legs are named." -->

**Maturity:** GA

"Verified" always answers two questions: **what** was verified, and was verification **full or degraded**. A bare "verified" is never printed.

## The legs

Every patch, whether a rule's stored fix, a zero-model deterministic swap, or one an agent composed, goes through the same gate before it is written:

| Leg | Passes when | If it cannot run |
|---|---|---|
| Re-scan | The original finding is gone and no new medium-or-higher finding appeared | Fails closed |
| Lint | The linter is clean | Skipped, and named |
| Tests | The project's tests pass | Skipped, and named |
| Honesty gate | A completeness tier is assigned and its residual-risk text is consistent | Fails if inconsistent |
| Proof-of-concept | The finding's PoC no longer demonstrates the vulnerability against the patch | `inconclusive` is never counted as a pass |

If the patch does not pass, it is not written.

## Full versus degraded

`ok` and `verifiedFull` are different claims:

- `ok`: nothing that ran failed.
- `verifiedFull`: nothing that ran failed **and nothing was skipped**.

`degradedLegs[]` names exactly what was skipped. The CLI says so on the verified line:

```text
verified: yes, but NOT fully verified — rescan clean, no new medium+ finding; lint: eslint not installed
```

A degraded pass is never presented as a full one.

## Completeness tiers

| Tier | Meaning |
|---|---|
| `FULL` | The sink signature changed, every caller is routed through the fix, and a test fails before the patch and passes after. Carries no residual-risk text. |
| `MITIGATION` | Anything short of the three signals above. Must document the residual risk. |
| `WORKAROUND` | A rate-limit-only, docs-only or log-without-reject change. Capped here whatever else is true. |

A residual-risk guard rejects hand-wavy claims such as "adequately handled" or "properly validated" when the mechanical evidence contradicts them.

## Three vocabularies, never blended

The closed-loop verdict (`verified-clean`, `verification-failed`, `untested-but-passes`), the mechanical result object, and the `FULL` / `MITIGATION` / `WORKAROUND` tier answer three different questions. They are kept as three. See the [walkthrough](../walkthroughs/verified-remediation.md) for each with captured output, including a rejected fix.

A fourth, unrelated surface exists: `agentic-security verify` re-runs the verifier loop on *findings* (is this finding real), not on fixes.

## Stronger: proof-gated fixes (Preview)

`fix --apply --require-proof` refuses to write unless the original exploit reproduces beforehand and is demonstrably blocked afterward. See [exploit proof](../guides/exploit-proof-fabric.md#verified-remediation-fix---require-proof).

## What verification does not establish

<!-- limits-verified: 2026-10-19 -->

- That no other weakness exists.
- That a `MITIGATION` or `WORKAROUND` removed the underlying issue.
- That a re-scan stopping the detector means the vulnerability is closed. Only the proof-of-concept leg re-executes the exploit.
