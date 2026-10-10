# Business-logic invariants: shrinking, repair, coverage and the ablation

An executable invariant is a reviewer-approved statement of what must never happen to durable state (one tenant's data changed by
another, an unprivileged role changing a limit, a workflow step skipped, value created from nothing, a request taking effect
twice). The scenario engine runs bounded adversarial sequences against a disposable fixture and judges the durable state that
results, not the response code. This page covers what happens after a scenario finds something, and what the tooling will and
will not say about the result.

Everything here sits behind the `invariant-scenarios` feature, which is off by default and operator-only (set
`AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS=1`; a project file cannot enable it). Running a scenario also needs
`verification-oracles`, and verifying a repair also needs `patch-negative-verification`. With the features off, scan output is
byte-identical to what it was. Linux is not claimed: these have been executed on the macOS userspace backend only.

## Shrinking a failing sequence (X-405)

`shrinkScenario` searches for a smaller sequence that reproduces the same violation, within a fixed budget (a number of replays
and a wall-clock ceiling, both with hard limits). It only removes: an attack step, one member of a parallel group, a control
step, or a seed record. It never edits, reorders or adds a step, so every surviving step keeps its actor, and the invariant,
tenants, roles, forbidden outcomes and pinned fixture cannot change.

A removal is kept only if the replay settles `confirmed`, every precondition holds (the control flow visibly worked and cleaned
up, and the attack reproduced itself across two fresh runs), and the SAME authoritative failing assertion fires. The
authoritative assertion is the first violated outcome in the contract's own order. Records a surviving step addresses, and
records that carry a marker the assertions look for, are setup dependencies and are never offered for removal; each such
decision is listed, with its reason.

The result carries a content-addressed record linking the original and the minimized scenario by digest, replay manifest id,
verification record id and receipt digest, plus every attempt. `verifyShrinkRecord` recomputes those links and re-derives, from
the two scenarios alone, that the minimized one is a removal-subset of the original.

What it reports instead of hiding: `minimal: false` when the budget ran out; a parallel group means cooperative scheduling in one
process (two fresh runs are compared and a disagreement is no verdict); a fixture that reads clocks, randomness, timers,
network or third-party packages is reported as a signal that a network-less disposable replay cannot hold constant. Those are
pattern checks over the fixture text, a disclosure and not a proof.

## Verifying a repair (X-406)

`verifyInvariantRepair` is `verified-fix` only when all of these are shown by executed, receipted runs:

1. the violated contract is approved in a verifying ledger (a repair of a model-proposed or code-inferred contract is never a
   verified fix, and nothing is executed for it);
2. the exploit reproduces on the original and not on the patched revision, using the same four-run discipline, promotion and
   repair ledger as every other repair (`verifyPatchNegative`, with the business-state oracle as the declared behaviour check);
3. the authorized workflows still work (the scenario's control flow plus any workflows you declare), on the original as a
   baseline and on the patched revision;
4. every other approved contract on the same fixture still holds: its bounded scenarios run on both revisions. A violation that
   appears only on the patched revision blocks; one already on the original is reported as pre-existing. Proposed contracts are
   advisory and not required.

Anything else blocks with an explicit reason code: `feature-disabled`, `bad-request`, `invariant-not-approved`, `setup-failed`,
`unsupported-check`, `original-not-reproduced`, `violation-not-eliminated`, `authorized-workflow-broken`, `workflow-regression`,
`workflow-check-inconclusive`, `workflow-baseline-invalid`, `invariant-regression`, `preservation-inconclusive`,
`preservation-unsupported`, `patched-check-inconclusive`, `oracle-changed`, `environment-mismatch`, `promotion-refused`,
`revision-unbound`, `artifact-refused`. A blocked result is never verified.

A verified repair yields a regression artifact: the exact patch, the invariant revision with its approval evidence, the exploit
scenario and one pinned replay manifest per leg with its expected outcome. Re-run it from the file alone, in a new process:

```
agentic-security invariants regress artifact.json
```

Exit 0 means every leg settled as recorded, 1 means one did not (or the artifact is invalid or was edited), and 3 means it was
not run (a prerequisite is unmet or a feature is off): not-run is never a pass. The artifact embeds the fixture and patch source,
so it is refused if either holds a credential.

Only the declared scenario, the declared workflows and the other contracts' bounded scenarios are exercised. A verified fix does
not mean the patch is correct anywhere else.

## Coverage and scenario export (X-407)

```
agentic-security invariants coverage --invariant contract.json [--ledger ledger.json] [--results runs.json]
agentic-security invariants export   --invariant contract.json --fixture ./fixture-dir [--commit <sha>] [--output out.json]
```

The coverage report lists approved versus proposed contracts (judged by the verified ledger: a document that only claims
approval is not approved), the actors, states and transitions the executed scenarios drove against what each contract declares,
and the gaps. Gaps are never removed by running more of the same: untested transitions, actors and states; the sequence depth the
scenarios were bounded to; races a class cannot model (and the cooperative-scheduling limit where one was run); scenarios that
could not be built or did not settle; contracts that do not exist for a class. It states that it describes a bounded sample and
never claims exhaustive correctness. With the feature on and a coverage object attached to a scan, the JSON and CLI reports gain
an `invariantCoverage` field; with it off, they are unchanged.

The export is the reproducible package for one contract: scenario documents with content digests, the fixture digest they pin,
replay manifests when a commit is given, the bounds that applied and what could not be built. It never includes the fixture
source. A scenario holding secret-looking content is withheld (named by path, never by value) rather than exported with a hole in
it. The MCP tool `invariant_scenario_export` is the same function, read-only and confined to the session root.

## The held-out ablation (X-408)

`npm run bench:invariant-ablation -- run` compares three arms over one frozen benchmark with one denominator and one budget:
source-only analysis, an inferred (unapproved) contract, and the approved contract. An arm that cannot evaluate a case keeps it
in the denominator as a miss and names it. Precision and recall carry Wilson 95% intervals; every arm is compared with the
baseline on the same cases with paired counts; unique findings and scenario cost are reported. A class is called supported only
from executed evidence that meets the registered policy and loses no baseline-found defect; if nothing could be executed the
class reads UNMEASURED.

**The benchmark is synthetic.** Its 15 small applications and their labels were written by the tooling's developers, in the
factory shape the oracle can run, and no independent adjudication exists. It is frozen (`manifest.json` lists the digest of every
file; `pin.json` pins the manifest) and the loader fails closed on any change; changing a case is a new version with a new pin.
The figures exercise the comparison. They are not engine accuracy and they are not evidence of real-world benefit, and the
baseline arm is looking at framework-free factories, which is not the code it is built for.
