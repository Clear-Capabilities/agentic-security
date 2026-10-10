# Assurance features: supported scope and contracts

What the verification, deployment, invariant, capability-enforcement, portfolio and routing features cover today, what they need
before they run, and where the evidence for each statement lives. Read this before relying on any of them.

**Every feature on this page is off by default and changes nothing in a default scan.** The ones that execute code are
operator-only: a file inside the scanned project can never turn them on. **The evidence in this repository is synthetic** (small
fixtures written by the people who wrote the tools), so these pages describe a mechanism that has been exercised, not accuracy on
real programs. No real-code accuracy gate has been met; see [measurement status](measurement-status.md).

Two pages are generated from the code and checked by a test, so they cannot drift from it:

- [Assurance capability matrix](../reference/assurance-capability-matrix.md): features, oracles, prerequisites, platforms,
  deployment adapters, invariant classes and bounds, and the enforcement backend per platform.
- [MCP tool contract](../reference/mcp-tool-contract.md): every MCP tool with its read, mutating or external classification and
  the checks made before it runs.

## Coverage at a glance

| Area | What is covered | What is not claimed | Evidence |
|---|---|---|---|
| Runtime oracles | Eight adapters: injection execution, authorization decision, state transition, side-effect reachability, parser resource, replay idempotency, functional regression, business state. Targets are JavaScript modules run under Node. | Any other language as an oracle target. A detector finding in another language is not made verifiable by this. | [oracle fixtures](../../scanner/test/fixtures/oracles), [conformance guide](verification-oracle-conformance.md) |
| Verified fix | A repair is a verified fix only when the original reproduces the exploit, the patched revision does not, and declared behaviour still holds, each in an executed, receipted run. | That the patch is correct anywhere outside the declared scenario and cases. | [patch-negative tests](../../scanner/test/verification/patch-negative.test.js) |
| Non-taint classes | Tenant authorization, privileged action, workflow order, replay or idempotency, bounded resource exhaustion. | Concurrent races, cross-site request forgery and authentication throttling are named as unsupported. | [non-taint tests](../../scanner/test/verification/non-taint-classes.test.js) |
| Deployment boundaries | Kubernetes and Compose adapters are validated against a frozen synthetic set. Terraform plan and IAM policy ingest, but carry no deployment-aware claim. | Runtime traffic coverage, gateway authentication semantics, network-policy denial by absence of an allow. | [deployment guide](deployment-aware-support.md), [ablation test](../../scanner/test/deployment/differentiation-ablation.test.js) |
| Business invariants | Five contract classes (tenant isolation, privilege constraint, value conservation, workflow order, idempotency) run as bounded adversarial sequences against a disposable fixture. | Exhaustive business correctness; durable state outside an in-memory store; true parallelism. | [invariants guide](business-logic-invariants.md), [scenario tests](../../scanner/test/invariants/invariant-scenarios.test.js) |
| Capability enforcement | Runner-level file, command and network mediation with active probes, hash-chained receipts, and a malicious-repository test corpus. | Linux outcomes (unverified). macOS is host-proved for development only and is not an advertised enforced backend. Windows is unsupported. | [capability tests](../../scanner/test/capabilities), [capabilities notes](../../scanner/src/capabilities/CLAUDE.md) |
| Portfolio and assurance | Leased work units, dependency-aware resume, retention with legal holds, offline-verifiable bundles, a signed bounded claim. | Independent certification. A signature here is self-issued. | [portfolio tests](../../scanner/test/portfolio), [assurance review](assurance-review.md) |
| Model routing | Shadow decisions, a paired offline replay and a promotion gate, drift detection and rollback. | Any cost or quality advantage. No real routing outcome exists in this repository. | [routing replay](routing-replay.md), [routing policy card](routing-policy-card.md) |

## Oracle prerequisites

An oracle declares what it needs. Each prerequisite is checked against the host before anything runs; an unmet one is reported
`unsupported` with the reason, the target is never executed, and the result is never a pass and never a failure of the hypothesis.

| Prerequisite | Meaning |
|---|---|
| `node-runtime` | Node.js 24 or later. |
| `confinement-backend` | A confinement backend that passes its functional probe on this host. On a host where it does not, the boundary refuses to run. |
| `posix-shell` | Needed by the injection-execution oracle only. |

Platform status is per oracle and per platform and comes from the oracle manifest, not from this page: macOS is where the
repository's tests were executed (`supported`), Linux is `unverified` (no Linux outcome is claimed and the run reports
`unsupported`), and Windows is `unsupported`. The exact table is in the [capability matrix](../reference/assurance-capability-matrix.md).

## Verification states

Six outcomes stay distinct: `not-run`, `unsupported`, `inconclusive`, `error`, `refuted` and `confirmed`. Repair status is a
separate field (proposed, applied, replay-verified, rolled back). `refuted` needs an applicable oracle and proven preconditions: a
missing taint path is never a refutation of an authorization or workflow claim. A model's opinion is `inference` evidence only and
cannot produce `confirmed`. See [schema migration](verification-schema-migration.md) for what a consumer reads.

## Deployment adapters

| Adapter | Status |
|---|---|
| `kubernetes` | validated on the frozen synthetic set |
| `compose` | validated on the frozen synthetic set |
| `terraform-plan` | ingests; not validated for deployment-aware claims |
| `iam-policy` | ingests; not validated for deployment-aware claims |

"No path found" means the supplied files did not show one, nothing more. A path is possible, blocked or unresolved; an old or
sampled trace cannot establish complete reachability. Detail and the paired counts are in the
[deployment guide](deployment-aware-support.md).

## Invariant limits

Proposed or inferred contracts are advisory until a named human approves them in a signed local ledger. A generated scenario is
bounded by actors, depth, requests, scenario count and wall time, each with a hard ceiling that rejects rather than clamps (values
are in the capability matrix). The assertions judge durable effects, not response codes. A clean result covers only the declared
scenarios. See [business-logic invariants](business-logic-invariants.md).

## Enforced-backend capabilities

An enforced task is released only on an advertised backend with every control it depends on proved by an active probe. On the
platforms in this repository: Linux is advertised and `partially-verified` (the filesystem, environment, no-network, tree-termination and file-size controls are
proved by active probes on the hosted `sandbox-linux` job only; mediated network is not implemented there, so a task that declares a
network destination is blocked, and process-count caps are never claimed); macOS is `host-proved-not-advertised` (a task can run there for
development when the caller opts in, and the result says it is not enforced); Windows has no backend. A hook response, a tool
allowlist or the presence of a container does not prove isolation. The standing limitations are listed on the matrix page.

## Contracts and where to read them

| Contract | Source |
|---|---|
| Verification record (`agentic-security/verification-record`) | [scanner/src/posture/assurance/verification-record.js](../../scanner/src/posture/assurance/verification-record.js) |
| Capability manifest (`agentic-security/capability-manifest`) | [scanner/src/capabilities/manifest.js](../../scanner/src/capabilities/manifest.js) |
| Release assurance manifest (`agentic-security/release-assurance-manifest`) | [scanner/src/posture/portfolio/manifest.js](../../scanner/src/posture/portfolio/manifest.js) |
| Boundary drift record (`agentic-security/boundary-drift`) | [scanner/src/lineage/deployment/drift.js](../../scanner/src/lineage/deployment/drift.js) |
| Invariant scenario export (`agentic-security/invariant-scenario-export`) | [scanner/src/posture/invariants/export.js](../../scanner/src/posture/invariants/export.js) |
| MCP tools | [MCP tool contract](../reference/mcp-tool-contract.md) |

## Next steps

- Run the examples: [runnable assurance examples](assurance-examples.md).
- Operate it: [background controller](background-controller-operations.md), [portfolio recovery](portfolio-recovery.md) and
  [assurance review](assurance-review.md).
- Check the measurement claims: [policy cards and measurement status](assurance-documentation-index.md).
