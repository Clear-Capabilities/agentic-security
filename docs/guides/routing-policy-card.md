# Routing policy card

What the calibrated model router decides, on what evidence, under which constraints, and how it is checked before it may change
anything. It describes `scanner/src/posture/routing/` and the offline replay in [routing replay](routing-replay.md). For the status
of every figure read [measurement status](measurement-status.md).

**Status: machinery, not evidence.** No real routing outcome and no adjudicated routing task exists in this repository. Every
population in the tests and in the reproduction is generated, is marked `synthetic`, and reads `unmeasured`. **No cost or quality
advantage is claimed anywhere.** Routing is behind the `model-routing` feature, which is off by default; with it off, the router
returns exactly what it returned before, and a test pins that against recorded outputs.

## What it decides

Four task kinds are routed separately, because the right model for one is not the right model for another: discovery, triage,
verification planning and repair. A decision applies hard constraints in this order and only then minimises measured cost or
latency: availability, capability, privacy, context window, quality (the **lower** bound of the interval must meet the minimum),
interval width, evidence freshness, and budget. Each rejected candidate lists every constraint it failed. When nothing is
acceptable the result is `fallback` (the existing capability route, quality marked unverified, and only if it passes capability,
privacy, context and budget) or `blocked` with a code. A constraint is never relaxed to find a route.

## Dataset provenance

| Item | Provenance |
|---|---|
| Tasks and strata | A stratum key is `kind`, `language`, `vulnerability class` and a context-size bucket. Real tasks would come from the operator's own runs. |
| Outcomes | An outcome record keeps every status: failed, timeout, cancelled, provider error, partial, blocked. A count that was not reported is `null`, never zero. The ledger has no remove or overwrite. |
| Truth labels | A decided label comes only from independent adjudication (a human or verifier service that is not the model or its provider) or from trusted execution (a verification record). Provider agreement, self-reported confidence, an accepted suggestion, a model's own judgement and a majority vote are refused as truth labels, and the outcome is recorded `unknown`. |
| Prices | A versioned price book built from the provider catalog, which is a dated snapshot and not live truth. Unknown is `null` or a bounded estimate, never zero. |
| What exists here | Generated populations only ([routing fixtures](../../scanner/test/helpers/routing-fixtures.js)), flagged `synthetic`. |

## Leakage controls

| Control | Effect |
|---|---|
| Held-out calibration | Quality is fitted on one side of a time split and a model-version split and judged on the other. Versions are never pooled. A group on both sides is removed from the held-out side and counted. |
| Frozen task set | The comparison tasks and their strata are fixed by hash before any outcome is looked at (`freezeTaskSet`). |
| Paired replay from recorded outcomes | Both arms are scored on the same frozen tasks. A paid replay needs an injected invoker and a bounded authorization (who approved it, a call count, a spend and a per-call ceiling); otherwise it is offline. |
| Shadow mode | The policy records what it would choose and returns production's own route unchanged. It holds no transport, so it cannot make a paid call. |
| Protected feedback | Only registered human adjudicators and trusted verifier services can label an outcome, each record signed with the actor's key. The first label is the original; a change is a correction that cites it. Unauthorized, unverifiable, tampered, duplicate or poisoned feedback is quarantined, excluded from calibration and counted by reason. |
| Data handling | Source or evidence reaches a provider only when the task policy and the egress policy both allow it, and only through the guarded adapter. Redaction depends on pattern checks, which are not proof against every secret shape. |

## Supported strata

**None.** A stratum can be called supported only when the overall gate passes and the stratum itself has at least 30 paired
adjudicated tasks. The report lists unsupported strata and unmet gates, and a stratum that meets the criteria on its own sample is
still unsupported while the overall gate reads anything other than `pass`. Calibrated quality is labelled `reliable` only with at
least 200 paired adjudicated tasks overall, 30 per stratum, a measured interval and a stable development-versus-held-out rate; a
synthetic population only ever earns `reliable-synthetic`.

## Denominators

The report states exact counts: frozen tasks, paired tasks, dropped tasks, adjudicated pairs and unadjudicated pairs. A failed arm
is never dropped: a failure status, a timeout, a task the proposed policy left unserved or a blocked proposal counts as not-correct
in the quality comparison and is reported in a per-arm failure table. A pair whose correctness is still unknown is counted as
unadjudicated and kept out of the quality statistic, never imputed. In the reproduction on this page's date: 240 frozen, 240 paired,
0 dropped, 240 adjudicated, 0 unadjudicated, all generated.

## Uncertainties

Quality difference carries a 95% grouped-bootstrap interval (proposed minus baseline); below 10 groups it is `unmeasured`. Cost and
latency are medians and percentiles with unknown values left unknown. The gate needs the interval's lower bound above -0.02, and,
on the quality-gain path, above zero as well. In the generated reproduction the interval was -0.0625 to -0.0166 around a difference
of -0.0375, so the quality criterion was unmet; that says the gate can fail a loss, not anything about a model.

## Economics

Measured cost splits input, cached input, output, retries and tool execution, and names the price version, currency and billing
basis. A prediction is never written into the measured field. Cost bounds cover model tokens; tool execution is priced by the
caller's runner. The promotion criterion is a median cost at least 20% lower, or quality at least 0.05 higher (with its lower bound
above zero) at no higher median cost, with p95 latency at most 1.2 times the baseline, retries, cached input and tool execution
inside the measured cost. An unknown cost makes the cost criterion unmet, never zero. The reproduction printed a 50.0% median cost
reduction on its generated tasks; that is arithmetic on invented prices and is not a finding.

## Safety, drift and rollback

A canary is finite by construction: a task count, a spend budget, an error rate, a consecutive-error limit and an incorrect-rate
limit. A trip restores the previous known-good policy and keeps every receipt. A change in model version, a price change, a schema
change or recent quality below the calibrated lower bound invalidates the affected estimates and sends the policy to the
documented state `fallback` or `shadow`. Activation needs a `pass` verdict from the promotion gate. Controls: `AGENTIC_SECURITY_ROUTING`
set to `adaptive`, `disabled` or `pin:<model>`, and the kill switch `AGENTIC_SECURITY_NO_MODEL_ROUTING=1`. No command-line flag is
wired to these yet. Every decision goes into a hash-linked receipt log, which is tamper evidence for the holder of the export and
not a signature.

## Known failure modes

| Failure mode | Effect | Status |
|---|---|---|
| No real outcomes | The gate cannot pass; it reads `unmeasured` on synthetic data and `insufficient-population` on a short real one. | Open: needs adjudicated routing tasks. |
| Cherry-picked or dropped pairs | Would flatter the result. | The verdict reads `invalid` (`cherry-picked`, `dropped-tasks`). |
| An edited replay or frozen set | Would change the result after the fact. | `invalid` (`replay-edited`, `frozen-set-edited`). |
| Unbounded paid replay | Would spend without limit. | Refused before any call (`UNBOUNDED_REPLAY`); a replay that reaches its bound is `truncated-replay`. |
| New model version, price change, different cache conditions | The calibration no longer applies. | A new evaluation; drift detection invalidates the estimates. |
| A flipped trusted-execution label | The feedback store cannot recompute a trusted-execution label from the outcome alone, so a flip of one is not detected there. | Documented limit. Adjudicated labels can be recomputed. |
| Catalog capabilities | The catalog carries prices and cache models but not capabilities or context windows, so the operator supplies them and an unknown window is rejected. | Documented limit. |

## Reproducing this card

`npm run reproduce:routing` rebuilds the report, the card and the receipt chain offline in under a second and runs seven controls
that must each behave. The policy card hash is in [measurement status](measurement-status.md). See
[offline reproduction](offline-reproduction.md) and [routing replay](routing-replay.md). The evaluation counterpart is the
[evaluation policy card](evaluation-policy-card.md).
