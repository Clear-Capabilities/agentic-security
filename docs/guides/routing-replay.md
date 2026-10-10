# Routing replay and policy card

How the calibrated model router (X-601 to X-604) is validated before it is allowed to change anything, and how to repeat that
validation offline. Nothing here needs a network, a provider account or a hosted service.

**Status in this repository: machinery, not evidence.** No real routing outcome and no adjudicated routing task exists here. Every
population in the tests and in the reproduction is generated, is marked `synthetic`, and reads `unmeasured`. No cost or quality
advantage is claimed anywhere, and the reproduction cannot produce one.

## The path from a proposal to a promotion

1. **Shadow mode** (`routing/shadow.js`). The constrained policy decides which model it would pick and writes that proposal down.
   Production keeps using its own route: `shadow()` hands back the object it was given. The recorder has no transport and no provider
   adapter, so it cannot make a paid call. If adaptive routing is disabled, nothing is decided or recorded.
2. **Frozen task set** (`freezeTaskSet`). The tasks used for the comparison, with their strata, are fixed by hash before any outcome
   is looked at.
3. **Paired replay** (`replayPaired`). For every frozen task the baseline arm (the model production used) is paired with the proposed
   arm (the model the shadow decision chose), from recorded outcomes. A paid replay is possible only with an injected `invoke` and a
   bounded authorization (who approved it, a call count, a spend, and a per-call ceiling charged for any unknown cost). Without both it
   is offline. A replay that reaches its bound stops and leaves tasks unpaired.
4. **The promotion gate** (`evaluatePromotion`), the routing row of the PRD evaluation table:
   - at least 200 paired adjudicated tasks overall and at least 30 per promoted stratum;
   - the lower 95% bound on the quality difference (proposed minus baseline) above -0.02;
   - the measured median cost at least 20% lower, or quality at least 0.05 higher (with its lower bound above zero) at no higher
     median cost;
   - p95 latency at most 1.2 times the baseline.
   Retries, cached input and tool execution are inside the measured cost. An unknown cost makes the cost criterion unmet, never zero.
5. **Canary** (`routing/canary.js`), finite by construction: a task count, a spend budget, an error rate, a consecutive-error
   (outage) limit and an incorrect-rate limit. A trip restores the previous known-good policy and keeps every receipt. Activation needs
   a `pass` verdict from step 4.

## What invalidates the gate

The verdict reads `invalid` whatever the figures say when:

- the paired tasks are not the frozen set (an extra task, a repeated task, or a replay built on a hand-picked subset): `cherry-picked`;
- a frozen task has no pair (no shadow record, a missing or ambiguous outcome, or a replay that ran out of bound): `dropped-tasks`;
- a replay was edited after it was built, or the frozen set was: `replay-edited`, `frozen-set-edited`;
- paid calls were made without a valid authorization or past its bounds, or the replay stopped at its bound: `unbounded-replay`,
  `truncated-replay`.

A failed arm is never dropped. A failure status, a timeout, a task the proposed policy left unserved or a blocked proposal counts as
not-correct in the quality comparison, and is reported. A pair whose correctness is still unknown is counted as unadjudicated and kept
out of the quality statistic, never imputed. A synthetic population reads `unmeasured`.

## Drift and rollback

`routing/drift.js` snapshots what a policy was promoted on (calibration hash, model versions, price digests, schema versions,
calibrated quality) and compares it with the present:

| Drift | What is invalidated |
| --- | --- |
| model version changed, or model gone | that model's estimates |
| price entry changed | that model's measured cost (decisions use the catalog upper bound); its quality stands |
| a record or calibration schema changed | every estimate |
| recent decided outcomes significantly below the calibrated lower bound | that model and stratum |

Any invalidation sends the policy to the documented state `fallback` (the existing capability route stands; invalidated estimates are
refused by the constrained router) or `shadow` (proposals are recorded, production is unchanged), chosen by `onInvalidation`. A canary
told about drift rolls back.

## Feedback protection

`routing/feedback.js`. Only registered adjudicators (human) and trusted verifier services can label an outcome; each record is signed
with the actor's key. The first accepted label is the original and is never changed; a change is a correction that cites the entry it
corrects. Only an allowlist of metadata fields is kept. Source code or evidence is sent to a provider only when the task policy
explicitly allows that kind of payload and the egress policy (or a capability manifest) also allows it, and then only through the
guarded provider adapter. Unauthorized, unverifiable, tampered, duplicated or poisoned feedback is quarantined, excluded from
calibration, and counted by reason.

## Controls

| Setting | Effect |
| --- | --- |
| `AGENTIC_SECURITY_ROUTING=adaptive` | the default |
| `AGENTIC_SECURITY_ROUTING=disabled` | the existing capability route, no constrained decision |
| `AGENTIC_SECURITY_ROUTING=pin:<model>` | that model, no optimisation (sending a prompt still passes the egress policy) |
| `AGENTIC_SECURITY_NO_MODEL_ROUTING=1` | the kill switch for the whole feature |

An explicit option (`routingOptions: { routing: '...' }` on `routeModelWithPolicy`) beats the environment. A value that cannot be read
fails closed to `disabled`. This switch is in the routing function; no command-line flag is wired to it yet.

Every shadow decision, replay, promotion verdict, drift assessment, canary event, rollback and feedback decision goes into a
hash-linked receipt log. `exportReceipts` produces a portable file and `verifyReceiptChain` checks it with no other input. It is tamper
evidence for the holder of the export, not a signature and not independent certification.

## Reproduce it offline

```
cd scanner
npm run reproduce:routing
```

(Equivalent: `node scripts/routing-replay.mjs` from the repository root. Add `--json` for machine-readable output, and
`--receipts <file>` to write the exported receipt chain.)

It builds a generated population, runs shadow decisions through a paired offline replay, prints the replay report and the policy card
hashes, and then runs controls that each must behave for the path to be trusted:

| Control | What must happen |
| --- | --- |
| `synthetic-never-passes` | a synthetic population with passing arithmetic reads `unmeasured`, and no claim is allowed |
| `gate-discriminates` | a generated population that meets the criteria passes, a quality loss at far lower cost fails, 120 tasks is insufficient |
| `cherry-pick` | removing the failed pairs after the fact invalidates the gate |
| `dropped-failures` | leaving failed outcomes out of the record invalidates the gate |
| `unbounded-replay` | a paid replay with no bounded authorization is refused before any call |
| `reproducible` | a rebuild gives the same report hash and the receipt chain verifies |
| `control-honoured` | disabling or pinning adaptive routing changes what `routeModelWithPolicy` returns |

Exit 0 means every control behaved; exit 1 names the control that did not. To see the script can fail, break one on purpose:
`node scripts/routing-replay.mjs --fault cherry-pick` (also each other control name) must exit 1 and name that control.

The `pass` that `gate-discriminates` shows is the arithmetic on a generated population. It says the gate can distinguish good from bad
input, and nothing about any model.

## Reading the report

The report states exact denominators (frozen, paired, dropped, adjudicated, unadjudicated), the quality difference with its 95%
interval or the reason it is unmeasured, the measured median and total cost, the cache states of both arms (unknown stays unknown),
latency p50 and p95 for both arms, and a failure table per arm. Claims are limited to strata the gate passed and the model versions
tested. Unsupported strata and every unmet gate stay listed, and a stratum that meets the criteria on its own sample is still
unsupported while the overall gate reads anything other than `pass`.

## Limits

- The calibration, the replay and the gate describe the tested strata and model versions only. A new model version, a price change or
  different cache conditions is a new evaluation.
- Catalog prices are a dated snapshot, not live truth. Cost bounds cover model tokens; tool execution is priced by the caller's runner.
- A trusted-execution label carries its verification record id only when it is made, so a flipped label on an outcome that already
  carries one cannot be recomputed by the feedback store. Adjudicated labels can be.
- Redaction depends on the egress redaction patterns, which are pattern checks, not proof against every secret shape.
- Reproducing the evaluation proves the arithmetic repeats. It does not prove any population was adjudicated independently.
