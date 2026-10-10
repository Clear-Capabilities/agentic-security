# Assurance documentation index

The pages that document the verification, deployment, invariant, capability, routing and portfolio features, grouped by what you
are trying to do. Every one of them is checked by `npm run test:documentation`, which runs the commands the pages quote and fails
if a referenced command, script, schema or fixture path no longer exists, if a generated page differs from the code, or if a page
states an unbounded claim about safety or scope.

**Read first:** no real-code accuracy gate has been met, the evidence in this repository is synthetic, Linux enforcement is
unverified, macOS is host-proved only, and a signature in this system is self-issued rather than independent certification.

## Know what is supported

| Page | Use it to |
|---|---|
| [Supported scope and contracts](assurance-scope-and-contracts.md) | See what each feature covers, what it needs and what it does not claim, with links to evidence. |
| [Capability matrix](../reference/assurance-capability-matrix.md) | Look up an oracle, adapter, invariant class or platform. Generated from the code. |
| [MCP tool contract](../reference/mcp-tool-contract.md) | Look up a tool's read, mutating or external classification. Generated from the code. |
| [Verification schema migration](verification-schema-migration.md) | Move a consumer to the version-1 verification record. |
| [Oracle conformance](verification-oracle-conformance.md) | Add or check a runtime oracle. |
| [Deployment-aware support](deployment-aware-support.md) | Learn which deployment adapters are validated. |
| [Business-logic invariants](business-logic-invariants.md) | Shrink a failing sequence, verify a repair, read coverage. |

## Try it

| Page | Use it to |
|---|---|
| [Runnable assurance examples](assurance-examples.md) | Run an original and patch replay, a tenant invariant, a graph drift, a blocked capability and a migration, locally. |

## Check a measurement claim

| Page | Use it to |
|---|---|
| [Measurement status](measurement-status.md) | Tell historical baselines, new synthetic measurements and aspirational targets apart. |
| [Evaluation policy card](evaluation-policy-card.md) | See how the evaluation is built, protected and where it fails. |
| [Routing policy card](routing-policy-card.md) | The same for the model router. |
| [Offline reproduction](offline-reproduction.md) | Rebuild the evaluation and the routing replay from the recorded manifests. |
| [Evaluation reporting](evaluation-reporting.md), [routing replay](routing-replay.md), [bake-off recipe](bakeoff-recipe.md), [miniature reproduction](miniature-reproduction.md), [engine mechanism evidence](engine-mechanism-evidence.md) | Deeper detail behind the cards. |

## Operate and review

| Page | Use it to |
|---|---|
| [Operating the background controller](background-controller-operations.md) | Start a finite run, watch it, pause it, cancel it, recover it and verify it. |
| [Loop runbook](loop-engineering.md) | The full controller command reference. |
| [Portfolio recovery](portfolio-recovery.md) | Recover a multi-repository audit and read its progress. |
| [Offline assurance review](assurance-review.md) | Decide what a signed claim shows and what it does not. |
| [Staged rollout and rollback](assurance-rollout-and-rollback.md) | Promote a feature through its gates, check a release against one exact commit, roll back, and migrate past the CORE-003 bundle verifier break. |
