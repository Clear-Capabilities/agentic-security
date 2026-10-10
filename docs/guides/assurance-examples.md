# Runnable assurance examples

Five local examples, each a command you can run now, each with the output it printed when this page was written and the exit code
that went with it. Every one uses synthetic fixtures already in the repository, needs no network and no account, finishes in
seconds, and asks nothing on a terminal. Nothing here runs against your code.

**Where they were run.** macOS, Node 24.20.0, on the repository's userspace confinement backend. **Linux is unverified:** the
repository's tests have not been executed on a Linux host for these features, so no Linux output is shown and none is claimed. On
a host that cannot run the confinement boundary, the execution examples print why they did not run and exit 3, which is a
statement that nothing was verified, not a pass.

All commands run from `scanner/`. The `agentic-security` command in the examples is `node bin/agentic-security.js` from a
checkout.

| Example | Command | Exit when it behaves as described |
|---|---|---|
| Original and patch replay (a verified fix) | `npm run verification:patch-example` | 0 |
| Tenant invariant | `npm run example:tenant-invariant` | 0 |
| Graph drift | `npm run example:graph-drift` | 0 |
| A blocked capability | `npm run example:blocked-capability` | 0 |
| Migration of legacy verification shapes | `npm run example:migration` | 0 |

## 1. Original and patch replay: a verified fix

A re-scan that no longer fires proves the detector went quiet, and a cosmetic edit can do that. A repair counts as a verified fix
here only when four executed, receipted runs show it: the original revision reproduces the exploit, the patched revision does
not, and the declared behaviour holds on the original (a baseline) and on the patched revision.

First the single replay, which reproduces one verdict twice from a pinned manifest:

```
npm run verification:replay-example
```

```text
manifest rpl:ce0ecfebc6c7f8d4 pins commit aaaaaaaaaaaa, fixture sha256:6b92db44c8d3, oracle injection-execution@1
first run:  outcome confirmed, reproduced expected: true, record vrec:66a3e16d5a82fa52
second run: outcome confirmed, reproduced expected: true, record vrec:66a3e16d5a82fa52
replay reproduced the verdict and the record id
```

Exit 0. Then the full original and patch check, using the oracle fixture pair
([injection-execution](../../scanner/test/fixtures/oracles/injection-execution)) as the vulnerable and fixed versions:

```
npm run verification:patch-example
```

```text
patch sha256:a94efcd6dc61 against a1a1a1a1a1a1
original-positive: passed (oracle outcome confirmed, expected confirmed)
patched-negative: passed (oracle outcome refuted, expected refuted)
functional-baseline: passed (oracle outcome refuted, expected refuted)
functional-regression: passed (oracle outcome refuted, expected refuted)
result: verified-fix (declared scenario and cases only)
```

Exit 0. The other direction: the same command with `--still-vulnerable` swaps in a cosmetic edit (the original plus a comment).
The patched-negative run still confirms the exploit, so nothing is promoted and the later steps do not run:

```
npm run verification:patch-example -- --still-vulnerable
```

```text
patch sha256:de944a544df0 against a1a1a1a1a1a1
original-positive: passed (oracle outcome confirmed, expected confirmed)
patched-negative: failed (oracle outcome confirmed, expected refuted) [patched-still-exploitable]
functional-baseline: not-run
functional-regression: not-run
result: NOT verified-fix (patched-still-exploitable)
```

Exit 0, because "refused as described" is the expected result of that variant. What this shows and what it does not: the declared
exploit scenario and the declared cases were exercised in a disposable workspace with no network. It does not show the patch is
correct anywhere else. The features `verification-oracles` and `patch-negative-verification` are off by default and these
scripts turn them on for their own process only. Read [oracle conformance](verification-oracle-conformance.md) for the contract.

## 2. A tenant invariant

An executable invariant states what must never happen to durable state. This example runs one reviewer-approved tenant-isolation
contract against two synthetic applications from the [frozen benchmark](../../scanner/test/fixtures/invariant-benchmark/cases):
one writes another tenant's invoice, the other rejects the write first.

```
npm run example:tenant-invariant
```

```text
invoices-cross-tenant-update [tenant-isolation]: 1 bounded scenario(s) run, 1 settled, 1 approved violation(s)
  cross-tenant-access: forbidden durable state reached: no-cross-tenant-write in the attack sequence (gus (tenant globex) changed 'invoices/acme-1' owned by tenant acme)
tickets-tenant-scoped [tenant-isolation]: 1 bounded scenario(s) run, 1 settled, 0 approved violation(s)
scope: these bounded scenarios on these two synthetic applications only; a clean result is not a proof of correctness
```

Exit 0. The contract is approved in a local ledger by the benchmark's own fixture reviewer, which is how the benchmark works and
is not a real review: in use, only a human named by your reviewer policy can approve. The verdict comes from the durable write,
not from a response code. With the feature off, the scenario export is refused:

```
node bin/agentic-security.js invariants export --invariant test/fixtures/invariant-benchmark/cases/invoices-cross-tenant-update/contract.json --fixture test/fixtures/invariant-benchmark/cases/invoices-cross-tenant-update
```

```text
agentic-security invariants export: disabled: invariant-scenarios is not available: default: off
```

Exit 1. Setting `AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS=1` for that one command prints the reproducible scenario package
(exit 0; add `--output <file>` to write it). The export never contains the fixture source. See
[business-logic invariants](business-logic-invariants.md).

## 3. Graph drift

The boundary graph is built from deployment files. This example builds it for two revisions of the same synthetic service, one
without an ingress and one with a public ingress, and reports what changed. The inputs are the two directories under
[k8s-ingress-vs-internal](../../scanner/test/fixtures/deployment-ablation/cases/k8s-ingress-vs-internal).

The `boundaries` command builds one graph. It is off by default:

```
node bin/agentic-security.js boundaries --from test/fixtures/deployment-ablation/cases/k8s-ingress-vs-internal/exploitable
```

```text
agentic-security boundaries: not run (disabled): default: off
The deployment-boundaries feature is off by default. Enable it for one run with AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES=1.
```

Exit 3. With the feature enabled for the one command (`AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES=1`):

```text
Deployment boundaries (environment prod)
  Graph: 5 node(s), 7 edge(s), 0 gap(s), 0 unresolved; digest sha256:03e0b
    manifests.yaml: kubernetes (ingested)
  Traces: not-supplied
  Scan result: not supplied, so no finding was analyzed
Deployment boundaries: 0 finding(s) with context; 0 bound to a service, 0 not bound; traffic coverage is not established
  Configured relationships were not exercised and runtime traffic coverage is not established; a path that is not listed has not been shown to be absent.
```

Exit 0. Then the drift between the two revisions:

```
npm run example:graph-drift
```

```text
before: 6 node(s), 9 edge(s), digest sha256:89bac
after: 5 node(s), 7 edge(s), digest sha256:03e0b
Boundary drift: 7 change(s), 3 material
  [material] new-exposure: route 'ingress/shop/public:shop.example.com/api' is reachable from an exposed entry point and was not before
  [material] new-exposure: route 'svc/shop/api' is reachable from an exposed entry point and was not before
  [material] new-exposure: service 'shop/api' is reachable from an exposed entry point and was not before
  connectivity-added: new routes-to ingress/shop/public:shop.example.com/api -> svc/shop/api
  connectivity-removed: removed assumes shop/batch -> sa/shop/default
  connectivity-removed: removed network-allows shop/batch -> shop/api
  service-removed: service 'shop/batch' is no longer in the graph
  source changed: manifests.yaml (supported 9 edge(s) before, 7 now)
  This compares two configured graphs; it does not show how the deployed system behaves.
```

Exit 0. Material categories are new exposure, changed privilege, tenant-boundary weakening and removed controls; the other changes
are reported but not material. `npm run example:graph-drift -- --reverse` swaps the two revisions, so the same exposure reads
as `exposure-reduced` and the three material rows become one `changed-privilege` row. Drift also drives which findings need a
rescan; unchanged components are not rescanned, and a finding that cannot be tied to a service makes the plan incomplete. See
[deployment-aware support](deployment-aware-support.md).

## 4. A blocked capability

A capability manifest is deny-by-default. This example binds a manifest that grants reading one directory and nothing else, and
shows three refusals. Nothing is executed in any of them.

```
npm run example:blocked-capability
```

```text
1. read of ~/.ssh/id_ed25519: deny (outside-roots)
2. unlisted command /bin/echo: blocked, code capability-denied, executed false, policy command-not-listed
   proposal (data only, not applied): missing command (command-not-listed), risk scope-addition, self-grantable false
3. isolation-required task on darwin without the development opt-in: unsupported, code platform-unsupported, executed false
all three were refused; nothing was executed
```

Exit 0. Read the three lines as follows. (1) The policy decision denies a path outside every declared root. (2) The runner
blocks a command the manifest does not list and returns a reviewable proposal of the narrowest change; the proposal is data for
an operator, and the task cannot grant it to itself because the signing key lives in a different domain. (3) Without the
development opt-in, an isolation-required task on this platform is `unsupported`: macOS can supervise but is not an advertised
enforced backend. **On Linux** the same call is expected to end `blocked` with the missing control named, and that is **not
verified**: the namespace backend does not yet implement all the controls, and no Linux run is shown or claimed. A hook response
is advice; only the runner stops a task. The platform table is in the
[capability matrix](../reference/assurance-capability-matrix.md).

## 5. Migrating legacy verification shapes

The version-1 verification record replaces three older vocabularies. The migration rule is that evidence can be lost, never
invented, so no legacy shape reaches `confirmed` or `refuted` by itself:

```
npm run example:migration
```

```text
a boolean `true`
  version-1 outcome: inconclusive; reason: legacy boolean true carries no oracle evidence
  legacy view: verified null, status inconclusive
a proof-tier object (ran, tier execution-proven)
  version-1 outcome: inconclusive; reason: legacy execution proof predates trusted-runtime-proof classification; re-verify under the trusted verifier to confirm
  legacy view: verified null, status inconclusive
a status string "skipped"
  version-1 outcome: not-run; reason: legacy status 'skipped'
  legacy view: verified null, status not-run
no hypothesis id supplied: refused (MISSING_FIELD)
every migration behaved as described: undecided stays undecided, and a missing id is refused rather than guessed
```

Exit 0. A consumer that tests `verified === true` cannot be told a skipped check passed, and one that tests `verified === false`
cannot be told an unrun check failed. The field-level migration notes are in
[verification schema migration](verification-schema-migration.md).

## If an example does not behave as described

Run `npm run test:documentation` and `npm run docs:check-assurance`. The first runs these commands and compares them with what
the pages say; the second checks that every command, script, schema and fixture path a page names still exists. If a command
exits 3, your host cannot run the confinement boundary: that is reported, and nothing was verified.
