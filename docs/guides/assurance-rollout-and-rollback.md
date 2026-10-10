# Staged rollout and rollback of the assurance features

How each new assurance feature moves from "the code exists" to "an operator may rely on it", how a release is checked against one
exact commit, and what a rollback does and does not restore. Everything here is local and offline; nothing calls a model or a
network.

**Status: machinery, not evidence.** No feature has been promoted on real input. The rollout ledger, the gates and the closure
record are exercised on synthetic fixtures only, Linux enforcement stays unverified, and a signature in this system is self-issued,
not independent certification.

## The three stages

Every feature in `scanner/src/posture/assurance/config.js` is off by default. Turning it on is not the same as trusting it. The
rollout policy in `scanner/src/posture/assurance/rollout.js` adds a stage to each feature, and a feature enters a stage only
through `promote`, one step at a time, with evidence for every gate of the stage it is entering.

| Stage | What runs | Can a result change a verdict, exit code or report line? |
|---|---|---|
| `offline-fixtures` | The feature against recorded fixtures in tests only. | No. A real run is refused. |
| `shadow-canary` | The feature beside existing behaviour on real input or a named canary subset. Results are recorded. | No. A shadow result is never used. |
| `opt-in-supported` | The feature, because an operator enabled it, the platform is supported and every gate is met. | Yes, and only here. |

Stages cannot be skipped. Evidence for a lower stage does not open a higher one, a gate that names a suite accepts evidence for
that suite only, and evidence without a sha256 digest is not evidence. The kill switch (`AGENTIC_SECURITY_NO_ASSURANCE=1` or the
per-feature switch) blocks promotion, and opt-in is blocked on a platform where the feature is unsupported.

`effectiveMode` combines the configuration with the stage. A feature an operator enabled but that is still at `offline-fixtures`
reports mode `fixtures`; at `shadow-canary` it reports `shadow`; only at `opt-in-supported` does it report `active`. With the
default configuration, or the kill switch, every feature is `off` at every stage.

## The documented gates

A gate is `suite` (a recorded closure step is the evidence), `measurement` (a bench or recorded run produced the artifact) or
`review` (a named person or process signed off). Suite gates take their evidence from the release closure record below.

| Stage | Gate | Kind | What must be shown |
|---|---|---|---|
| `offline-fixtures` | `fixtures-green` | suite, the feature's own suite | The feature's suite passes against recorded fixtures. |
| `offline-fixtures` | `default-off-unchanged` | suite, `foundation` | With the feature disabled, scan and report behaviour is unchanged. |
| `shadow-canary` | `fixtures-green` | suite, the feature's own suite | The suite still passes at the commit being promoted. |
| `shadow-canary` | `shadow-no-outcome-change` | measurement | A recorded shadow run on real input changed no verdict, exit code or report line. |
| `shadow-canary` | `rollback-rehearsed` | suite, `release-closure-suite` | Rollback was rehearsed and restored known-good behaviour without erasing evidence. |
| `opt-in-supported` | `fixtures-green` | suite, the feature's own suite | The suite passes at the commit being promoted. |
| `opt-in-supported` | `compatibility-holds` | suite, `compat-nix` | Existing Haskell/Nix and core-language behaviour is unchanged. |
| `opt-in-supported` | `documentation-current` | suite, `documentation-suite` | Scope, examples and the policy card for the feature are published and drift-checked. |
| `opt-in-supported` | `canary-record` | review | A shadow-canary record exists with no unresolved incident. |

Each feature adds its own opt-in gate, taken from the targets in the product requirements rather than invented here.

| Feature | Own suite | Extra `opt-in-supported` gate | What it requires |
|---|---|---|---|
| `verification-oracles` | `verification` | `oracle-conformance` | Every advertised adapter passes positive, negative, inconclusive and tamper controls; unavailable prerequisites are reported unsupported. |
| `patch-negative-verification` | `verification` | `repair-evidence-triple` | Every advertised verified fix carries original-positive, patched-negative and functional-regression evidence bound to the exact environment, patch and oracle. |
| `deployment-boundaries` | `deployment` | `paired-ablation` | A frozen contextual ablation shows additional confirmed defects or fewer false positives with unchanged scoring and no lost baseline defect. |
| `invariant-scenarios` | `invariants` | `contract-approval-path` | Contracts are approved by an authorized reviewer, never by the generator that proposed them. |
| `capability-enforcement` | `capabilities` | `backend-probes` | Every mandatory canary-secret and escape fixture is blocked on the advertised backend with zero canary leakage. macOS stays supervise-only. |
| `model-routing` | `routing` | `promotion-thresholds` | At least 200 paired adjudicated tasks overall and 30 per promoted stratum, a quality lower bound above -0.02, and the cost and latency targets. |
| `portfolio-assurance` | `portfolio` | `interrupted-run-convergence` | Interrupted, duplicate-delivery and incremental runs converge to a fresh scoped result with no double-counted progress. |

No feature has met its extra gate on real data. Several of them cannot yet, because the population or the Linux backend does not
exist here; they stay at the stage their evidence supports.

## Checking a release against one exact commit

`scripts/release-closure.mjs` runs the new suites and the existing controller, smoke, bundle-source (which runs the build),
documentation, scorecard and Haskell/Nix/core-language compatibility checks against the current commit, and writes a record.

```
npm run release:closure:static
npm run release:closure:check
```

`release:closure:static` is cheap and runs in the pre-push gate: it fails when the plan lacks a required area, a script or test file
is missing, a new suite is not part of the full test run, or the gate is not in a release group. `release:closure:check` is the
full run, registered in the release gate as `release-closure-gate` and given its own parallel leg in the release workflow.

The record names the commit and tree, whether the tree was clean, a digest of the plan, and for every step its state, command,
exit code, test counts, the suite version and the sha256 of its log. The suite version covers the script text and the digest of
every test file it names. A record is invalid, and its evidence is not publishable, when:

- it is bound to a different commit or tree, or the working tree is dirty now or was dirty when it ran;
- the commit or tree changed while the closure ran;
- a step is in the plan but has no recorded result, or the record names a step the plan lacks, or the plan changed;
- a suite's script or test file changed after it ran;
- a log no longer matches its digest, or is not retained.

A skipped or todo test, a zero-test run, a timeout and a non-zero exit are never a pass. The record is written outside the tracked
tree, under a `release-closure` folder in the `.agentic-security` state directory, so measuring a commit does not dirty it.

### Remote prerequisites are not counted

Two steps need something this machine may not have: the Haskell tests that need a real GHC toolchain, and the NixOS host runtime
suite. Locally they are `unsupported`. They are not run, they are not in the passing count, and the local gate does not report
them as passed. The record is `localOk` for what ran here and stays not publishable until a hosted CI attestation for the same
commit and the same step says `success`. An attestation for another commit, a failed run or another step does not count. A step
that does run locally and fails is a hard failure, not a pending prerequisite.

## Rollback

`planRollback` and `applyRollback` in `scanner/src/posture/assurance/rollback.js` restore the last known-good position.

- The target is the most recent known-good ledger entry at an earlier stage. From `opt-in-supported` it is `shadow-canary`; from
  `shadow-canary` it is `offline-fixtures`; at `offline-fixtures` the only known-good behaviour is the feature being off, and the
  plan returns the configuration change for the operator to apply. Nothing edits configuration for you.
- The rollout ledger is append-only. A rollback adds an event and restores the position and policy version; history is never
  rewritten. Policy versions are never reused, so a record made under a rolled-back policy stays identifiable after a later
  re-promotion.
- Evidence and claims are only ever annotated. A record produced under a policy newer than the restored one is flagged `stale`. A
  record of a kind with no previous reader is flagged `incompatible`. A claim that rests on any flagged or missing record is flagged
  too. The evidence store is not touched, and the plan lists every id it retained.
- A feature that fails does not erase anything. `guardedFeatureRun` turns a throw into a typed `blocked` result and records the
  failure; `EvidenceStore` has no operation that removes or overwrites an item (the same id with a different digest is refused),
  and a file-backed store reports a torn last line instead of trusting it.

### What rollback can and cannot restore

`READER_POLICY` records, per record kind, whether a previous reader is retained.

| Kind | Previous reader retained | What a legacy consumer sees |
|---|---|---|
| `verification` | yes, `toLegacyVerificationView` | `status` and `reason`; `verified` is true only for confirmed, false only for refuted, otherwise null. |
| `evidenceBundle` | yes, `verifyWithPreCore003Reader` | Only bundles re-exported without the issuance block. |
| `observationBinding` | no | Nothing. The binding is new; the records are kept and flagged `incompatible`. |
| `capabilityDecision` | no | Nothing. A decision is never turned back into a bare allow or deny. |
| `routingLabel` | no | Nothing. A boolean label has no place for a label source. |
| `releaseEvidence` | no | Nothing. A legacy check list cannot carry evidence references. |

A rollback never claims an old consumer can read what it cannot. Where no previous reader exists, the new records stay readable by
the current reader and are flagged for anything older.

## Known compatibility break: verifiers older than CORE-003

CORE-003 added a signed `issuance` block to evidence bundles (who signed, and that the trust basis is a self-issued local key). The
bundle verifier rejects any top-level key outside its allowlist, because that rule stops an unsigned field being stapled onto a
signed bundle. A verifier older than CORE-003 does not list `issuance`, so it rejects every newly signed bundle with
`unrecognised top-level key(s) not covered by the signature: issuance`. The reverse is fine: the current verifier reads old bundles
and reports them as `none-declared`, meaning no trust basis was declared, not that one was proven.

The strict rule is not loosened to hide this. `verifyWithPreCore003Reader` is a faithful copy of the old verifier, and a test shows
both the break and that an old verifier still rejects a bundle with a stapled field.

Migration path, in order of preference:

1. Upgrade the verifier. It reads both formats and reports the trust basis.
2. If a consumer cannot upgrade, produce a legacy export with `exportLegacyBundle(bundle, privateKeyPem)`. It first verifies the
   original under the matching key and refuses a tampered bundle or one this key did not sign, then re-signs the same content
   without the issuance block. The old verifier accepts it; the current verifier reports `none-declared`.
3. Keep the original bundle. The export loses the signed trust-basis statement. Because an old verifier rejects any extra key, the
   disclosure cannot ride inside the bundle, so `exportLegacyBundle` returns a sidecar record with both digests, the dropped
   issuance block and a note. Keep it beside the export. The export is a new signature by the same local key, so it is still
   self-issued and is not independent certification.
