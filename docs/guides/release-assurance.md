# Release assurance: package, verdict, views, offline verification

**Maturity:** Preview. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

A release package is one signed file holding the evidence for one build: the scan's health, the findings, any fix verification records and any runtime explanations. It answers one question, **"is there anything in this evidence that blocks the release?"**, and it answers it the same way every time, because the answer is a function of the package alone.

It never says a release is *safe*. The most it says is that no blocking or unknown condition was found in the evidence it holds.

## The three answers

| Verdict | Meaning |
|---|---|
| `not_deployable` | A blocking condition is present: the scan did not finish, files were not scanned, an analyzer timed out or failed, a fix was claimed and not fully verified, a finding is proven exploitable and open, or a high or critical finding is open |
| `needs_review` | Nothing blocks, but something is unknown and a person has to decide: a context signal the analysis could not settle, runtime records from a different build, deep analysis that stopped short |
| `deployable` | None of the above. This is **not** a statement that the release is safe |

Every blocker and unknown carries a sentence in words and the digest of the evidence it rests on. A finding marked a false positive without a named person and a reason is an unknown, not a pass. A waiver (a finding id covered by an honoured waiver) is listed, not hidden.

## Try it

The demo in `examples/assurance-demo` is scanned, triaged, validated, patched, verified, correlated with runtime metadata, signed and checked offline by one command, with no network (every attempt to open a connection is refused and counted):

```sh
node scripts/engineering-excellence/e2e-demo.mjs
```

The steps, as the implementation printed them:

<!-- capture: e2e-steps -->
```text
[start] copied examples/assurance-demo (10 files) to a scratch directory; offline mode on; every attempt to open a network connection is refused and counted
[scan] 9 findings (8 medium or above); scan health complete
[triage] 4 of 4 expected true positives were reported; 1 of 3 expected false positives were reported and marked by the reviewer; 3 reported finding(s) have no recorded decision
[validate] 3 candidate(s) from cross-route consistency and the tenant invariant; 3 became findings, 1 of them proven by an executed attacker request; 0 refuted. SQL injection and command injection stay taint findings: nothing was executed for them
[patch] 3 candidate patches applied to scratch copies (2 correct, 1 false fix)
[verify] 2 of 3 patches fully verified; the false fix passed the security re-analysis and the attack replay and was refused on behaviour (owner-can-update-own-note)
[sca] 2 vulnerable dependencies from the local advisory data; 1 reached by a call to the advisory's function, 1 imported but not reached
[runtime] collection is off until a policy file switches it on (first attempt: refused); after opt-in 2 records were ingested; /search is corroborated by the released build, the /notes/:id records came from an older build and corroborate nothing
[sign] release package with 10 evidence records signed with a throwaway Ed25519 key; the verdict computed from its own contents is not_deployable
[verify-offline] the independent verifier accepted the package (exit 0); a copy with one finding's severity lowered was rejected (exit 1); the stated verdict matches the one recomputed from the contents
```

### Build and check one from your own scan

```sh
agentic-security scan .
openssl genpkey -algorithm ed25519 -out release-key.pem
agentic-security release-package build . --private-key release-key.pem --public-key-out release-key.pub.pem --output release-package.json
node scripts/verify-release-package.mjs release-package.json --public-key release-key.pub.pem
```

`build` refuses a scan whose signature is missing or does not verify. It records the scan's health and one record per finding, computes the verdict from the package's own contents, and signs with your key. The key is yours: the package says `independentlyCertified: false`. The [release assurance contract](../reference/release-assurance-contract.md) lists every field, reason code and exit code, and the release gate runs this path on every release, including the refusals.

### Reading the package for a CISO

`release-view` renders the developer, CISO and auditor views of one package from the same findings, so they cannot disagree. Its help line:

<!-- capture: help-release-view -->
```text
  release-view <package.json>  Developer, CISO and auditor views of one signed release package (--view, --format text|json|html, --previous, --public-key)
```

The CISO view of the demo's package:

<!-- capture: release-view-ciso -->
```text
CISO VIEW
  release verdict: not_deployable. 2 condition(s) block the release.
    blocks: finding a669cb1ca1da1a6b is open at severity high
    blocks: finding ec61e1145b1dd25b is open at severity high
    unknown: finding 8b20a2064d9a3755 rests on a context signal the analysis could not settle (plausible)
    unknown: runtime records for 1 edge(s) of fd3e0e5433b6cb89 came from a different build than the one released, so they say nothing about this release and are not counted as corroboration
  scan: complete (complete)
  proven: 1 executed, 2 taint path, 2 unproven, of 5
  fixes: 2 verified, 0 unverified, 3 open
  since last release: no previous release was supplied
  verification: signature and contents verified
```

`--view developer|ciso|auditor|all`, `--format text|json|html`, `--previous <older package>` for what changed since the last release, and `--public-key` to say whether the signature was checked.

### Verifying offline

The verifier imports only Node built-ins and nothing from the code that builds a package, so a defect in the producer cannot make the verifier agree with it:

<!-- capture: verify-package -->
```text
release package verified: scan complete, 10 records, 5 findings
```

A copy whose evidence, scan health or verdict was changed is rejected, and so is a package signed by a key-holder whose stated verdict contradicts its own contents (the verdict is recomputed from the contents).

## What this does not do

- The default `scan` does not build or sign a package. The package is assembled by the demo script and by the library functions in `scanner/src/posture/assurance/`.
- The verdict policy is a fixed set of rules, not configurable per organisation, and not calibrated against outcomes.
- A scan that skipped a file for size or density is `partial`, and so blocks. That can surprise repositories with minified bundles or very large data files.
- The signing is a single Ed25519 key. Who holds the key and whether it is the right one is outside the package.

See also: [engineering-excellence index](../engineering-excellence/README.md), [scan health](../walkthroughs/scan-health.md), [fixing vulnerabilities](fixing-vulnerabilities.md).
