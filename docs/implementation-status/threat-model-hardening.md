# Implementation status: threat model hardening and release qualification

## Status summary (2026-11-08)

* **Baseline:** scanner 0.195.28 at `411ea8c2`. The bundle was rebuilt to the recorded SHA-256 `d61dba15…e2744c` before any change.
* **Branch:** `feat/threat-model-hardening`, local and unpushed, for review.
* **Local state:**
  * every locally verifiable requirement is `verified-local`;
  * no requirement is `verified-independent` or `verified-staging`.
* **Blockers:**
  * a staging deployment and alert destination authorized by their owners;
  * an independently held labelled population;
  * a runner that attests its confinement;
  * owner and responder sign-off.
* **Separate qualifications:** local, staging and independent evidence are kept apart in the candidate packet (the `tier` on every case) and are never reported as each other.

States follow the requirement's section 3 vocabulary:

* `pending`
* `reproduced`
* `implemented`
* `verified-local`
* `verified-independent`
* `verified-staging`
* `blocked`

Commands run from `scanner/` unless stated.

## Baseline behaviours

Each TM case is reproduced as a failing control in the test named for its requirement, and passes after the change.

| ID | State | Evidence |
| --- | --- | --- |
| TM-01 | verified-local | `test/invariants/approval-workflow.test.js` (wrong guard is a violation; corrected guard passes) |
| TM-02 | verified-local | `test/scope/scope-evidence.test.js` (tracked `buck-out/orders.js` reported under `scope.skippedByReason`) |
| TM-03 | verified-local | `test/deployment/iam-actions-and-limits.test.js` (a disjoint delete deny leaves the read possible; an unevaluated condition is unresolved) |
| TM-04 | verified-local | same file (maxHops=1 reports a depth cutoff; 8 hops finds the path) |
| TM-05 | verified-local | `test/deployment/proof-binding.test.js` (a revision A receipt does not promote a revision B path) |
| TM-06 | verified-local | `test/verification-independence.test.js` (two lenses from one verifier count once) |
| TM-07 | verified-local | `test/triage-memory-scoped.test.js` (a new high finding keeps its confidence) |
| TM-08 | verified-local | `test/egress-profile.test.js` (a malformed policy under the restricted profile denies before transport) |
| TM-09 | verified-local | `test/dnr/auth-truth-object-authz.test.js` (a rejected credential and a wrong tenant are detected; another route counts zero) |

## Requirements

| Requirement | State | Verification | Commit | Owner or blocker |
| --- | --- | --- | --- | --- |
| FR-01.1, FR-01.3 scope evidence in bundled JSON, inventory digest | verified-local | `node --test test/scope/scope-evidence.test.js test/scope/cli-scope.test.js` | `87b59fa8` | release engineering |
| FR-01.2 release scope reconciliation | verified-local | same; `scope/release-scope.js` | `87b59fa8` | qualified use needs an authoritative package inventory and route manifest per service |
| FR-02 workflow invariant and verified repair | verified-local | `node --test test/invariants/approval-workflow.test.js` (execution legs run through the trust boundary and report SKIPPED, NOT PASSED where it cannot run) | `bf38523c` | the independently held variant (FR-02.3) is blocked on an independent holder |
| FR-03 action-specific IAM decisions, honest path limits | verified-local | `node --test test/deployment/iam-actions-and-limits.test.js test/deployment/attack-paths.test.js` | `87b59fa8` | platform and IAM |
| FR-04 scope-bound proof, independent corroboration | verified-local | `node --test test/deployment/proof-binding.test.js test/verification-independence.test.js` | `e460b4e7` | harness maintainer and an independent AppSec reviewer |
| FR-05.1, FR-05.2 scoped learned decisions | verified-local | `node --test test/triage-memory-scoped.test.js test/triage-memory.test.js` | `1d84aab3` | |
| FR-05.3 sibling review queue | verified-local | `node --test test/sibling-queue.test.js` | `c10e2ada` | |
| FR-06.1, FR-06.2, FR-06.4 restricted egress profile | verified-local | `node --test test/egress-profile.test.js test/egress-policy.test.js test/egress-transport.test.js` | `1d84aab3` | privacy and operator security |
| FR-06.3 bound approvals | verified-local | `node --test test/mcp-approval-binding.test.js` | `c10e2ada` | |
| AC-06C execution cases on an attested runner | blocked | the four confinement-dependent cases stay skipped and visible on this host | | a runner that attests its confinement |
| FR-07 authentication truth, object authorization, target counter | verified-local | `node --test test/dnr/auth-truth-object-authz.test.js test/dnr/ir-and-outputs.test.js` | `a38986c2` | detection engineering |
| FR-08.1 two-tenant local fixture, PILOT-01 to PILOT-08 | verified-local | `node --test test/pilot/two-tenant-records.test.js` | `a38986c2` | service owner |
| FR-08.2 reference fixture and service qualification kept separate | verified-local | `node --test test/pilot/candidate-packet.test.js` (one packet per deployment identity) | `d455ba54` | each service's own qualification needs its own deployment identity |
| FR-08.3 app-to-cloud chain and database proof (PILOT-12) | verified-local | `node --test test/pilot/app-to-cloud-and-db.test.js` | `c10e2ada` | the path graph reasons about resource patterns, not individual objects |
| FR-08.4 staging delivery, sensor loss, replay (PILOT-10) | blocked | recorded as a blocked staging case in the pilot packet | | detection engineering and the incident lead; an authorized staging deployment |
| PILOT-09 independently withheld variant | blocked | recorded as a blocked independent case | | label custodian |
| FR-09.1 frozen protocol and custody | implemented (pre-existing) | `npm run test:evaluation` | | evaluation lead and label custodian |
| FR-09.2 every enrolled case reconciled, denominator preserved | verified-local | `node --test test/evaluation/scorer-reconciliation.test.js` | `d455ba54` | |
| FR-09.3, FR-09.4 floors and runtime measurement on the candidate | blocked | the candidate packet records G-06 as unmeasured | | an independently held population of at least 100 positives and 100 negatives per core language |
| FR-10.1, FR-10.2 candidate packet, gates recomputed from evidence | verified-local | `node --test test/candidate-qualification.test.js` | `4a573a40` | release owner |
| FR-10.3 strict qualification surface | verified-local | `agentic-security release-package qualify`; `node --test test/pilot/candidate-packet.test.js` | `d455ba54` | ordinary scan exit codes are unchanged |
| FR-10.4 upgrade, rollback and expiry invalidate a decision | verified-local | same file (`revalidateDecision`; `UNSUPPORTED_VERSION` for another packet version) | `d455ba54` | |
| AC-10C staged rollout and rollback | blocked | | | release owner; a staging deployment |

## The local candidate

`node bench/threat-model-pilot/qualify.mjs` runs the fixtures. It writes one signed packet and one decision per deployment identity. The run exits 1 only when a local case regresses.

The expected result on a developer host is "not qualified":

* G-03 is met for the export chain and the database search.
* The records service's G-03 is blocked by PILOT-09 and PILOT-11.
* G-04 is blocked: the runner is not attested.
* G-05 is blocked or unresolved: there is no staging evidence.
* G-06 is blocked: the population is unmeasured.
* G-01, G-02 and G-07 are unresolved until their evidence is supplied.

`docs/reference/release-assurance-contract.md` ("Candidate qualification") documents the packet, the tiers and the exit codes.
