# Offline assurance review

How a reviewer who holds only an evidence bundle, a signed claim and a trust-root policy decides what the claim shows. The review
runs offline: it reads files, recomputes hashes, checks one signature, and executes nothing from the bundle.

**A signature on an assurance claim is not independent certification.** The only trust basis this build can verify is
`self-issued-local-key`: the person or system that built the bundle also holds the key. The claim says so inside the signed bytes
(`independentlyCertified: false`), so it cannot be dropped or softened in transit. A valid signature proves the manifest and the
evidence it names are unmodified since signing. It does not prove a finding is real, that the scope was sufficient, or that a
replay would reproduce today.

**Status: machinery, not evidence.** Every manifest in this repository is synthetic (`synthetic: true`) and describes no real
release. No command-line verb signs or verifies a claim yet; the functions are `signAssuranceClaim`, `verifyAssuranceClaim` and
`buildTrustPolicy` in [scanner/src/posture/portfolio/signing.js](../../scanner/src/posture/portfolio/signing.js), and the walk-through below
calls them.

## What the reviewer receives

| Item | What it is |
|---|---|
| Bundle | A directory: `bundle.json` (the index) and `blobs/<sha256>` (one file per entry, named by its digest). It holds the assurance manifest, sanitized findings, finding provenance, replay manifests, toolchain identities and the verification receipts the manifest cites. |
| Signed claim | The manifest id and digest, the bundle digest, the subject repository and commit, the blocking policy, the blocking-finding count, coverage, the bounded headline, the signer id and key id, the assurance policy, and the issuance block (`self-issued-local-key`, not independently certified). |
| Trust-root policy | The reviewer's own list of keys they accept, with a basis for each, and a list of revoked key ids. Without one a signature means nothing, and the verifier says `NO_TRUST_POLICY`. |

## Run the walk-through

```
npm run example:assurance-review
```

About a second, no network, no terminal input. It generates a throwaway key in memory, builds a synthetic bundle in the OS temp
folder, signs it in the signer domain, then reviews it, and removes everything. Exit 0 when every step behaved as described. Its
output:

```text
1. a valid claim (the synthetic manifest has one incomplete mandatory check, so its scope is not full)
  ok   verified offline; trust basis self-issued-local-key; independentlyCertified false
    | No blocking findings in completed supported checks, but the mandatory scope is not fully covered
    | Scope: 2 of 3 mandatory checks completed, 0 waived, 1 incomplete, 0 unsupported. synthetic scope: two supported checks
    | Gaps: incomplete: replay (no confinement backend on this host) | residual risk: rr-1 (replay not executed)
    | Policy: policy-v1 (blocking severity high and above)
    | Synthetic fixture: this describes no real release.
    | Signature: valid under trust basis self-issued-local-key (self-issued, signer release-signer@example.test). It shows the manifest is unmodified; it is not independent certification.
    | This does not mean the software is safe or free of vulnerabilities, and a signature on it is not independent certification.
```

Read it in order: the headline, the scope count, the named gaps, the policy, and only then the signature line. The signature line
can add the trust-basis disclosure; it cannot soften the headline.

## Signature trust

The verifier fails, with a typed code, in each of these cases, and the walk-through shows them:

| Case | Code |
|---|---|
| The claim was edited after signing (a count, the headline, the signer, the policy) | `SIGNATURE_INVALID` |
| An evidence blob was modified or is missing, or the bundle index changed | `BUNDLE_INVALID` |
| The signing key is not a root in the reviewer's policy | `UNKNOWN_TRUST_ROOT` |
| The key is on the policy's revoked list | `REVOKED_TRUST_ROOT` |
| No trust policy was supplied | `NO_TRUST_POLICY` |
| A root's declared basis is one this build cannot verify (for example a third-party certification) | `UNSUPPORTED_BASIS` |
| The claim states independent certification, or its basis does not match the root | `OVER_CLAIM` |
| A valid claim is attached to a different, internally valid bundle | `EVIDENCE_MISMATCH` |

Signing is a signer-domain act. A worker, a target or a verifier asking to sign is refused before any key is read, and the
assurance key lives in its own directory and may be required to differ from the scan evidence key. The private key never appears
in an envelope, a policy or an error.

## Incomplete scope

Every mandatory check is in exactly one of four groups: completed, incomplete, unsupported or waived. An incomplete or unsupported
check names its gaps, and `complete` is derived from the lists, never trusted from the file. The headline changes with the
coverage: `No blocking findings in completed supported checks` is followed by `, but the mandatory scope is not fully covered`
when an incomplete or unsupported check remains. When blocking findings exist the headline reads `Blocking findings present in
completed supported checks`, followed by a count. The statement always says "completed supported checks": it speaks only for the
checks that ran. A claim that omits a mandatory check from every list fails validation.

## Waivers

A waiver is a check a named person chose not to require. It carries a reason and an approver, and the statement lists it under
Gaps:

```text
Gaps: waived: replay (no confinement backend on this host (synthetic); approved by reviewer@example.test) | residual risk: rr-1 (replay not executed)
```

Read a waiver as a gap accepted by that person, not as a check that ran. In this build a waived check counts toward the derived
`complete` flag, and a manifest whose only open items are waived reads `complete: true`; the statement still names every waiver and
every residual risk, so a reviewer should read the Gaps line, not only the headline.

## Expiry and freshness

**A signed claim carries no validity period in this build.** Its fields are the manifest and bundle digests, the subject
commit, the policy, the counts, the headline, and the signer; none is an expiry or a not-after date. A reviewer therefore applies
their own freshness rule. What does expire or go stale, and where:

| What | How it ages |
|---|---|
| Work-unit leases | A lease has an expiry; an expired lease is recovered and the old attempt's result is refused. |
| A verified result | Stale when any of six dependency digests (code, policy, graph, invariant, oracle, toolchain) changes; stale results never count. A claim resting on a stale unit is marked stale. |
| A signing key | Revoked by adding its key id to the trust policy. Revocation is the reviewer's own list; there is no network revocation service. |
| Retained evidence | Deleted by class once its retention period passes, unless it is a required current receipt or under a legal hold. |
| The subject | The claim names an exact commit. A different commit is a different subject; compare it with the commit you are reviewing. |

A reviewer who wants a time bound can require the claim to be re-signed on a schedule, or compare the signing date they recorded
out of band. Nothing in the bundle enforces it.

## Evidence retention

Retention is by class, with defaults and hard ceilings: replay evidence 365 days, metadata 730, model traces 30, secrets 0. A
required current receipt is never deleted even when it has expired, and is reported as expired but required. A legal hold, by id,
class or repository, blocks deletion, and a malformed hold refuses the whole plan. Every deletion is written to a hash-chained log
before the file is removed; the log holds digests and sizes, not content. See [portfolio recovery](portfolio-recovery.md). An
exported bundle is secret-checked on the way out (known secret shapes are redacted, then refused if any survives) and the importer
refuses a bundle that carries one. Snippets, taint traces and raw evidence stay behind.

## What to do before relying on a claim

1. Verify with a trust policy you wrote, not one shipped inside the bundle.
2. Read the headline, the coverage counts, the Gaps and the residual risks before the signature.
3. Check the subject commit is the one you are reviewing and apply your own freshness rule.
4. Read the replay prerequisites the verifier discloses. It does not attempt a replay; a replay needs the toolchain and, for
   execution, a backend that is **unverified on Linux and host-proved only on macOS**.
5. Treat the whole as a statement about the listed checks. It is not a statement that the software has no vulnerabilities, and it
   is not certification by anyone other than whoever holds the key.

Related: [scope and contracts](assurance-scope-and-contracts.md), [measurement status](measurement-status.md).
