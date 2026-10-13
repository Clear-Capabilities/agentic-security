# PRD 5 required-fixture killer scenario

PRD 5 (Source-to-Artifact Security & Provenance) names 7 required fixture properties and one "Killer
Demonstration". All 8 are proven end to end against the real built CLI in
`test/cli/artifact-provenance-cli.test.js` — no unit-test shortcut. Image archives are built in-memory at
test time via `test/helpers/build-tar-fixture.js` (a hand-rolled tar/OCI-layout writer, the production-code
mirror of `src/artifact/safe-tar.js`'s reader), rather than committing binary `.tar` fixtures to the repo.

| PRD-named property | Test | How it's proven |
|---|---|---|
| Vulnerable base package | `vulnerable base package vs. clean equivalent` | `image scan` against a docker-archive declaring `lodash@4.17.4` — real OSV advisories (via this repo's own disk cache; see the implementation-status doc's Verification section for the exact ids) |
| Clean equivalent | same test | the same archive shape with `lodash@4.17.21` — strictly fewer advisories, a different digest |
| Deleted-but-recoverable secret | `a secret deleted in a later layer...` | a 2-layer archive: layer 0 adds an AWS-access-key-shaped credential, layer 1 whiteouts it — `image scan` reports it under `secrets.deletedButRecoverable`, and the raw value never appears in any CLI output |
| Valid signature | `a valid detached signature verifies...` | a real Ed25519 keypair signs the scanned image's actual digest; `image verify --signature --public-key` reports `state: "verified"` |
| Invalid signature | same test | a signature over a DIFFERENT digest, verified against the same image, under the same key; `image verify` reports `state: "invalid"` and exits 1 |
| Incorrect provenance | `incorrect provenance (subject digest mismatch)...` | a validly-signed DSSE/in-toto attestation whose `subject` digest names a different artifact entirely; `image verify --attestation` reports `state: "invalid"` |
| Stale vulnerable deployment | `THE Killer Demonstration` | the PRD's own literal scenario: a source tree whose last scan is clean (the developer fixed the vulnerability) is compared, via `provenance trace --source`, against an older archive that still has it — `SOURCE: FIXED` / `DEPLOYED ARTIFACT: STILL VULNERABLE` / `PRODUCTION EXPOSURE: PRESENT`, printed verbatim in the PRD's own words |

Two additional tests cover behavior the PRD requires but doesn't name as one of the 7 fixtures: `supply vex`
producing a real status per advisory against the real CLI, and a hostile path-traversal tar entry being
surfaced (never crashing the process or silently vanishing) — the PRD's own Safety Requirements section.
