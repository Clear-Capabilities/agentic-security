# Verify

<!-- seo: title="Verify: Did the fix work, and which verification legs actually ran?" description="Stage 9 of the Agentic Security assurance lifecycle: Did the fix work, and which verification legs actually ran?" -->

**Stage 9 of 10.** Did the fix work, and which verification legs actually ran?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Verification is where a fix earns the word. Re-scan, lint, tests, the honesty gate and the proof-of-concept leg each report pass, fail or skip. The record says whether verification was **full** (`verifiedFull`) or **degraded** (`degradedLegs[]`), and a completeness tier (`FULL`, `MITIGATION`, `WORKAROUND`) says how much of the fix landed.

`fix --apply --require-proof` (GA) goes further: it refuses to write unless the original exploit reproduces beforehand and is blocked afterward.

`agentic-security repair` (Labs) verifies against an executable contract instead: for one SQL injection, object-authorization, server-side request forgery, path traversal, password-storage, vulnerable npm dependency or leaked-credential finding it runs the application itself (over a real SQLite file, a declared network or a real file tree) and accepts a candidate only when the declared attacks stop and the declared legitimate requests still work. See [Contract-driven repair](../guides/verified-remediation.md).

In CI, [assurance modes](../trust/assurance-modes.md) make an incomplete analysis fail the build in `strict` mode, and [CI gating](../workflows/ci-gating.md) wires both gates.

Do not confuse `agentic-security verify` (is this *finding* real, a verifier verdict such as `cannot-verify`) with fix verification (did this *patch* work). On the demo app, `verify --finding 'struct:server.js:11:SQL_Injection_(Template_Literal)'` returned `cannot-verify (no-poc-no-sanitizer-rule)`, which says nothing about whether the finding is true.

**Evidence this stage creates:** A verification record: legs, tier, degraded legs, and with `--require-proof`, a replay.

## Capabilities at this stage

<!-- generated:capabilities:verify:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Verified remediation](../trust/verified-remediation.md) | Verify | **GA** | Whether a patch passed its rescan, lint and test legs, which legs were skipped, and a completeness tier of FULL, MITIGATION or WORKAROUND. |
| [Contract-driven repair](../guides/verified-remediation.md) | Verify | **Labs** | For one SQL injection or object-authorization finding in a Node or Python (WSGI) application over SQLite, or one server-side request forgery, path traversal, password-storage, vulnerable npm dependency or leaked-credential finding in a Node application (a declared network, a real file tree, a stored credential the verifier recomputes), including a finding imported from another tool's SARIF report, whether a candidate patch stops the declared attacks and keeps the declared legitimate behaviour, judged in the trust boundary against an executable contract. Source-only; the trust boundary does not yet run on Linux. |
| [Proof-gated fix](../guides/exploit-proof-fabric.md) | Verify | **GA** | With `fix --apply --require-proof`, that the original exploit reproduced before the patch and is blocked after it. |
| [Assurance gate modes](../trust/assurance-modes.md) | Verify | **GA** | Whether CI fails on an incomplete analysis (strict) or only reports it (advisory, standard). |
| [CI gating](../guides/ci-setup.md) | Verify | **GA** | A baseline-aware pull request scan that writes SARIF, JUnit and JSON and applies a severity gate and an assurance gate. |
| [Release assurance](../guides/release-assurance.md) | Verify | **Preview** | A signed release package, an independent offline verifier and a deterministic not_deployable, needs_review or deployable verdict that names every blocker and never says safe. Not part of the default scan; `release-package build` assembles the package from the last scan, and the independent verifier checks it offline. |
<!-- generated:capabilities:verify:end -->

## Read more

- [Verified remediation](../trust/verified-remediation.md)
- [Verified remediation](../walkthroughs/verified-remediation.md)
- [Contract-driven repair](../guides/verified-remediation.md) and its [contract reference](../reference/repair-contract.md)
- [Assurance modes](../trust/assurance-modes.md)
- [CI gating](../workflows/ci-gating.md)

---

Previous: [Fix](../fix/README.md) · Next: [Detect](../detect/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
