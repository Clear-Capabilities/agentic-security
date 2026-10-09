# Verification oracle conformance

A verification oracle is a bounded, class-specific assertion about whether a hypothesis holds. It runs a target inside the trust
boundary, and the verdict is formed by verifier code from what the run left behind, never by the target. This page covers the
contract every oracle adapter must meet, the suite and release gate that enforce it, a bounded local replay you can run, and how
to add an oracle without widening what runs by default.

## What the contract requires

The suite is `scanner/src/posture/oracles/conformance.js`. It checks an adapter and never grants one anything: there is no
registration function, and the registry is built from the static adapter list when the module loads.

Static checks (no execution, any host):

| Check | An adapter fails it when |
|---|---|
| `class-scope` | its class is not a known oracle class; a platform lacks a stated status and note; Linux is claimed `supported`; prerequisites or limitations are not stated; its fixture directory is missing |
| `resource-budgets` | any of `timeoutMs`, `graceMs`, `maxOutputBytes`, `maxFileBytes`, `maxFiles` is missing, not a positive integer, or over the hard ceiling (`BUDGET_CEILINGS`) |
| `negative-controls` | it declares none, a control does not expect `refuted`, or the negative fixture is not a file on disk |
| `evidence-receipts` | it has no verifier-authored harness, `prepare` or `interpret`, or its logic digest does not match its logic |
| `pinned-fixtures` | the adapter logic or any of its positive, negative, inconclusive or scenario fixtures differs from `scanner/test/fixtures/oracles/conformance-pins.json`, or has no pin |

Execution checks (need a host where the trust boundary can run):

| Check | What it proves |
|---|---|
| `state-positive`, `state-negative`, `state-inconclusive` | the positive fixture confirms at the runtime-confirmed level, the negative refutes with proven preconditions, the inconclusive one stays open |
| `records-valid` | every record validates against the version-1 verification record |
| `authoritative-receipt` | the receipt was issued by the runner (a copy is not accepted), is immutable, names the record and the adapter logic digest, and the decided record carries trusted-runtime-proof from the trusted runner with sanitized environment metadata |
| `tamper-harness-rewrite` | a target that rewrites the adapter harness yields `error` and no receipt |
| `tamper-verdict-text` | a target printing verdict-looking text cannot move a refutation |
| `tamper-caller-verdict` | a request carrying a verdict or a receipt is rejected before anything runs |
| `unavailable-prerequisite` | an unmet prerequisite is `unsupported`, executes nothing and issues no receipt |
| `cancellation` | an aborted run is `inconclusive`, has no receipt and leaves no harness process behind |
| `replay` | running the pinned positive request again reproduces the outcome and the record id |

On a host where the boundary cannot run (Linux enforcement is not verified by this build, and the oracle platform statements
say so), the execution half is reported `not-run` with the reason. It is never reported as passed. Pass
`--require-execution` to turn that into a failure.

## Running it

```sh
cd scanner
npm run verification:conformance:static   # static contract and pins, under a second, runs in the pre-push gate
npm run verification:conformance:check    # static plus execution, about 20 seconds, runs in the release gate
```

Both run `scripts/verification-conformance-check.mjs` (`--static` skips execution, `--require-execution` fails when execution cannot run,
`--update-pins` re-pins deliberately). The release gate is the `verification-conformance-gate` check in `scripts/release-check.mjs`, in the `benches-b` group so the
parallel release workflow runs it. The test suite is `scanner/test/verification/oracle-conformance.test.js`
(`npm run test:verification`); it runs the suite over every registered adapter and over deliberately bad fake adapters to show
the gate rejects each one.

## A bounded local replay

`scripts/verification-replay-example.mjs` replays the pinned positive fixture of one oracle twice from a replay manifest:

```sh
cd scanner
npm run verification:replay-example                       # injection-execution
npm run verification:replay-example -- state-transition
```

Expected output (the ids are content hashes, so they match on your machine for the same fixture and toolchain):

```text
manifest rpl:... pins commit aaaaaaaaaaaa, fixture sha256:6b92db44c8d3, oracle injection-execution@1
first run:  outcome confirmed, reproduced expected: true, record vrec:...
second run: outcome confirmed, reproduced expected: true, record vrec:...
replay reproduced the verdict and the record id
```

What bounds it: the target is the repository's own fixture; it runs through the trust boundary only; the network is denied; writes
are limited to a disposable workspace; the oracle's own time and output budgets apply; the process tree is torn down and the
workspace removed before the verdict is read. The manifest pins the commit, the fixture hash, the toolchain, the oracle version
and logic digest, the inputs and the budgets, and it is rejected, with nothing executed, if any hash or scope is off. On a host
that cannot run the boundary the script prints why and exits 3; that is not a pass.

## Adding an oracle without expanding default execution permissions

Nothing below changes what a default scan, the CLI, the MCP server or a hook can run. The `verification-oracles` feature is off
by default, is high-risk execution (only an operator can enable it; a project file never can), and an oracle only ever runs
through `runInBoundary`. A new adapter inherits all of that and can add none of it.

1. **Write the adapter** with `defineOracle` in `scanner/src/posture/oracles/adapters.js`. Declare its class, the shared
   prerequisites it needs (you cannot invent a new way to run code), a status and note per platform (never `supported` on Linux),
   budgets under the ceilings, at least one negative control that expects `refuted`, and its limitations. The harness text is
   verifier-authored and only drives the target and writes a result document; `interpret` forms the verdict from what the run
   left behind.
2. **Add fixtures** under `scanner/test/fixtures/oracles/<id>/`: `positive/target.mjs`, `negative/target.mjs`,
   `inconclusive/target.mjs` and a shared `scenario.json`. The negative must exercise the same scenario as the positive and show
   the effect absent with the control proved; the inconclusive must never reach the check.
3. **Register it** by adding it to the static adapter list. There is no runtime registration, and a worker cannot add or edit
   an adapter.
4. **Pin it deliberately**: `node scripts/verification-conformance-check.mjs --update-pins`, and say in the commit why the
   pin moved. A changed fixture or changed adapter logic fails the gate until it is re-pinned, and changing what an adapter
   asserts means bumping its `version`.
5. **Run the suite**: `npm run verification:conformance:check`, then `npm run test:verification`.
6. **State the scope in the manifest**: the platform statements and limitations appear in every result a user sees. Do not claim
   a platform this repository has not executed.

What a new adapter cannot do, and what the gate checks: widen the replay scope (a manifest may name exactly its own oracle, no
network, workspace-only writes), exceed a budget ceiling, supply its own receipt (a receipt exists only if `runOracle` issued
it), or decide an outcome in the harness.

## Known limits

The target is imported into the harness process. A target written to recognise the oracle's payload and forge the effect
artifact is not distinguishable from a real injection: the oracle bounds the effect it tests, it is not a defence against a
target built to fool it. Receipts are valid inside the verifier's process; carrying one across processes needs a signing
domain, which is not part of this suite.
