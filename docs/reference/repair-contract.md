# Repair contract reference

This page fixes the shapes, outcomes and exit codes of `agentic-security repair` and the MCP tool `repair_plan`. It is the contract for the Labs capability `contract-repair`. Every table on this page is checked against the code by `scanner/test/contracts/repair.contract.test.js`: a field the code produces that the page does not list fails, and so does a field the page lists that the code does not produce.

How to use the workflow is in the [verified remediation guide](../guides/verified-remediation.md). This page says what each record means and what it does not establish.

## Commands and exit codes

| Command | What it does | Writes |
| --- | --- | --- |
| `repair plan` | Builds the contract from a finding, an application profile and the exact source. Executes nothing. | the plan file only |
| `repair run` | Judges candidates against the contract in the trust boundary; with `--apply`, writes a verified patch through the existing apply service. | the run record; project files only with `--apply` |
| `repair show` | Prints a stored run. A stored record is history: it carries receipt digests, never live receipts, and cannot promote anything. | nothing |
| `repair resume` | Re-runs a stored plan with its stored policy. Every verification leg is executed again in the new process. It cannot change the policy, the budgets, the candidates or the apply mode. | the run record |
| `repair cancel` | Asks a running repair, in any process, to stop. | a cancel marker |
| `repair export` | Writes the contract, the record, the exact patch bytes and a manifest to a directory. Request header values and any credential they carry are replaced by digests. | the export directory |
| `repair verify` | Checks an exported bundle: patch bytes against their digests, the contract against the manifest, and optionally whether the source under `--root` is the verified baseline or that baseline with the patch applied. Executes nothing. | nothing |
| `repair recipes` | `list`, `evaluate <recipe>` (executes the recipe's examples; needs `--allow-execution`), `promote`, `retire`, `rollback` (each needs `--reason`), `draft --file <recipe.json>`. Every change is a signed ledger record. | the recipe ledger |

**Exit codes**

| Code | Meaning |
| --- | --- |
| `0` | The requested operation completed. Read the disposition: a plan or an export exiting 0 does not mean anything was verified. |
| `1` | A required obligation failed, or the repair was rejected. |
| `2` | Usage or schema error. |
| `3` | A required prerequisite is unavailable, unsupported or blocked (execution not enabled, no backend, an incomplete profile, drifted source). |
| `4` | Cancelled, or a budget ran out before the requested verification completed. |

A run that requires verification never exits 0 while a required obligation is unexecuted.

## Application profile

A profile is declared by the operator: how to start the application and what its legitimate behaviour is. Nothing in it is inferred from code and presented as approved intent. A profile file that resolves inside the repository is repository-supplied input: its facts are recorded as `declared`, never `approved`. A profile cannot enable execution; there is no field that could.

**Profile**

| Field | Meaning |
| --- | --- |
| `schema` | `agentic-security/repair-profile` |
| `schemaVersion` | `1.x.y` |
| `application` | `entry`, `export`, `files` (every application file), `runtime`: `node` (a factory that receives `{ db }` and returns a Node request listener) or `python` (a factory that receives a `sqlite3` connection and returns a WSGI application) |
| `database` | `engine` (`sqlite`), `schemaSql`, `seed` (INSERT statements; `{{secret:<name>}}` plants a per-run value the application cannot know in advance) |
| `actors` | `id`, `tenant`, `role`, `headers` (how the actor authenticates), `anonymous` |
| `sql` | `inputs`: the untrusted value (`{{value}}` in the path or body), the actor sending it, legitimate values with their expected response (`originalMishandles` for one the original gets wrong), and the planted secrets another actor's data holds |
| `authorization` | `table`, `idColumn`, `contentColumn`, `objects` (owner, row id, planted secret), `operations` (`read` or `update`, with `{{id}}` and `{{value}}`), `policy.allow` (`owner`, `same-tenant-admin`, `any-admin`), and `controls`: legitimate workflows outside the actor matrix, such as a public page, that must keep working after a repair |
| `ssrf` | `policy` (`allowlist`: only the `approved` hosts; `public-only`: no loopback, private, link-local, carrier-grade NAT or unique-local address), `approved`, `hosts` (each with `name`, `addresses` answered one per resolution with the last repeating, so a host can rebind, an optional `port`, and `routes` the verifier serves: `path`, `status`, `headers`, `body`, where a body may plant `{{secret:<name>}}`), and `inputs` (the untrusted URL as `{{value}}`, the actor, and legitimate values with their expected response). Node runtime only. |
| `passwords` | `actor` (who registers and logs in), `table`, `userColumn`, `hashColumn`, `register` and `login` (method, path, body carrying `{{user}}` and `{{password}}`, `expectStatus`; `login.denyStatus` for a refused login), `legacy` (`digest`: the unsalted hex digest existing users carry, one of `md5`, `sha1`, `sha256`, `sha512`, and `users` with known test passwords; their rows are built from them), `approved` (`format`: `scrypt`, the only format the verifier recomputes in this release, with `minN`, `minR`, `minSaltBytes`, `minKeyBytes`). |
| `filesystem` | `root` (the allowed directory the factory receives as `filesRoot`), `tree` (relative path to content, inside and outside the root; a file outside it plants `{{secret:<name>}}`), `links` (real symbolic links, each resolving inside the tree), and `inputs` as for `ssrf`. Node runtime only. |
| `tests` | `command`, `required`, `flaky`: the project test suite the central verifier runs on both trees |
| `approval` | `approvedBy`, `reason`: counts only for a profile outside the repository |

## Contract

**Contract**

| Field | Meaning |
| --- | --- |
| `schema` | `agentic-security/repair-contract` |
| `schemaVersion` | `1.0.0`. A reader accepts 1.x; a 2.0 contract is refused. |
| `contractId` | `rcon:` and 16 hex characters over the allowlisted identity fields. Identical inputs give an identical id; no clock or random value enters it. |
| `contractDigest` | SHA-256 over the same fields. |
| `family` | `sql-injection`, `object-authorization`, `ssrf`, `path-traversal` or `password-storage` in this release. |
| `findingRefs` | The finding the contract repairs. |
| `rootCauseGroup` | Digest of the family and the finding's file. |
| `sourceCommit` | The commit the signed scan recorded, or null. |
| `sourceDigest` | Digest of the exact application files. A run against different source is refused. |
| `configDigests` | Lockfiles, `package.json`, `.nvmrc`, and the Node and SQLite versions. A change gives a different contract. |
| `profile` | The application entry, the database engine, the builder version and, for authorization, the full actor matrix. |
| `obligations` | What the repair must establish (table below). |
| `policyFacts` | The profile, with its origin and approval state. |
| `editScope` | `allowed` files, `prohibited` patterns (verifier state, tests, runner configuration, dependencies, version control), `maxFiles`, `maxEditedLines`. |
| `executionPolicy` | `trust-boundary` execution, network denied, no model. |
| `knownUnknowns` | What the contract does not observe. Always present. |
| `expiresAt` | Optional expiry. |
| `approval` | Optional approval identity. |

**Obligation**

| Field | Meaning |
| --- | --- |
| `id` | Stable within the contract. |
| `kind` | One of the registered kinds below; any other kind is refused. |
| `required` | Every obligation the builder emits is required. |
| `oracleId` | The registered oracle that runs it (`application-security`, `application-behaviour`), or null for the central verifier. |
| `oracleVersion` | The oracle version. |
| `oracleLogicDigest` | The oracle logic the contract pins. A changed oracle blocks the run until the contract is planned again. |
| `scope` | What the obligation covers. |
| `baselineExpectation` | The outcome required on the original revision, or null. |
| `patchedExpectation` | The outcome required on the patched revision. |
| `evidenceOrigin` | Where the obligation came from. |
| `inputs` | The declarative requests and read-only state checks. No contract carries executable assertion code. |
| `inputsDigest` | Digest of `inputs`. |
| `description` | The registered kind's description. |

**Obligation kinds**

| Kind | Runs on | Original | Patched | Meaning |
| --- | --- | --- | --- | --- |
| `app-attack-blocked` | `application-security` | confirmed | refuted | Development attack requests reach no forbidden effect; the legitimate requests in the same run still work. |
| `app-attack-sealed` | `application-security` | confirmed | refuted | Held-out attack variants, run only on a candidate that passed everything else. Their content and outcome never reach candidate generation. |
| `app-behaviour-preserved` | `application-behaviour` | refuted | refuted | Legitimate requests and state checks hold on both revisions. |
| `app-behaviour-after` | `application-behaviour` | not required | refuted | Legitimate requests the original mishandles hold after the repair. |
| `project-tests` | central verifier | not required | passed | Rescan, new-finding delta, footprint and the per-test delta of the project suite, through the same verifier every patch route uses. |

## Run record

**Record**

| Field | Meaning |
| --- | --- |
| `schema` | `agentic-security/repair-record` |
| `schemaVersion` | `1.0.0` |
| `runId` | `rrun-` and 16 hex characters. |
| `contractId` | The contract judged. |
| `contractDigest` | Its digest. |
| `findingRefs` | The finding. |
| `sourceDigest` | The source the run read. |
| `policyDigest` | Digest of the policy the run used. |
| `disposition` | `proposed`, `refuted-finding`, `needs-review`, `verified-for-contract`, `mitigation`, `rejected`, `blocked` or `cancelled`. |
| `application` | `not-applied`, `applied`, `reverted` or `concurrent-change-refused`. |
| `artifact` | Always `source-only` in this release: nothing is built. |
| `environment` | Always `not-checked` in this release: nothing is deployed. |
| `completion` | `complete`, `partial` (a budget stop), `cancelled`, `unavailable` or `invalid`. |
| `candidates` | Every candidate: round, generator, status (`verified-for-contract`, `passed-not-selected`, `rejected`, `refused`, `duplicate`, `inconclusive`, `cancelled`), the coordinator-computed scope and structural key, its rank among the round's survivors, the cross-execution result, and each obligation result with its receipt digest. |
| `selected` | The promoted candidate, or null. |
| `rounds` | Rounds used. |
| `obligationResults` | Original-revision results (recorded, not required) and the selected candidate's results. |
| `counterexamples` | Each failed obligation's shrunk request, actor and broken property. A sealed failure is recorded without its content. |
| `quarantined` | Legitimate-request expectations the original revision does not meet, each with its reason: they are removed from the obligations. |
| `regressionGuards` | Attacks (and generated state checks) the original revision already blocks, each with its reason. They stay in the obligations, so a candidate that removes an existing protection fails, but they cannot show a repair: an attack obligation still needs at least one check the original fails. |
| `budget` | The budgets in force and what was used. |
| `accounting` | Oracle runs, wall time, model tokens and calls, and cost. Unknown is null, never zero. |
| `reasons` | Notes, refusals and why the run stopped. |
| `nextPrerequisite` | The next thing that would let the run proceed, or null. |
| `scope` | The contract, the number of obligations and files, and the source-only statement. |
| `createdAt` | When the run started. Not part of any identity. |
| `patchDigest` | The selected patch's digest. |
| `exactPatch` | The selected patch's files and before and after digests. |
| `legacy` | The legacy `ok`, `verified` and `fixCompleteness` view. FULL means the named contract passed, not universal correctness. |
| `source` | Reserved for an artifact digest; an artifact or environment state needs it. |

**Dispositions**

| Disposition | When |
| --- | --- |
| `verified-for-contract` | A candidate passed every required obligation, including the sealed set and the central verifier, with live receipts bound to exactly its files. |
| `refuted-finding` | No declared attack reaches a forbidden effect on the original while its legitimate requests work. No patch is proposed. |
| `rejected` | Every candidate failed a required obligation. |
| `needs-review` | A result was inconclusive, or a required obligation had no check left that is meaningful on the original. |
| `blocked` | A prerequisite was missing: execution not enabled, no backend, an incomplete profile, drifted source, a changed oracle, or no candidate. |
| `cancelled` | Stopped by request or by signal. |
| `proposed` | Written at the start of a run, before any result. |
| `mitigation` | Reserved for a repair that reduces but does not remove the effect; not emitted in this release. |

## Profile support

What has been executed, per family, runtime and platform. macOS and Linux are separate: one platform's execution never qualifies the other. `declared` means the profile validates and a contract builds, but no test executes that combination. `repair plan` prints the row for its contract. This table is held to the code by the contract test.

**Profile support**

| Family | Runtime | macOS | Linux | Recipe |
| --- | --- | --- | --- | --- |
| `sql-injection` | `node` | integration-tested | blocked | `sql-parameterize-template` |
| `sql-injection` | `python` | integration-tested | blocked | none |
| `object-authorization` | `node` | integration-tested | blocked | none |
| `object-authorization` | `python` | declared | blocked | none |
| `ssrf` | `node` | integration-tested | blocked | none |
| `path-traversal` | `node` | integration-tested | blocked | `path-realpath-containment` |
| `password-storage` | `node` | integration-tested | blocked | none |
| `password-storage` | `python` | declared | blocked | none |

## Repair recipes

A recipe is a registered, hand-written transformation (code shipped with the scanner) plus a document: the family, language, runtime and driver it supports, its preconditions, the obligations its candidates must pass, its examples and its contraindications. A document cannot carry code or a command, and can only narrow a transformation (fewer files, a higher runtime floor), never widen it. A recipe is a proposer: what it produces is judged by every obligation of the contract like any other candidate.

The recipe's identity covers the document and the source of its transformation. An evaluation runs every example: positive and independent (held-out) examples must be `verified-for-contract` through the full coordinator, a safe-negative must be refused by the transformation, and an unsupported runtime version must be not applicable. The evaluation's digest covers the recipe identity, every example fixture and every obligation it was judged against; a promotion records it, and a recipe that changed after its promotion is not used.

**Recipe states**

| State | Used automatically | Meaning |
| --- | --- | --- |
| `shipped` | yes | A recipe shipped with the scanner, evaluated by this repository's recipe tests. |
| `draft` | no | An operator's narrowed recipe document, not yet evaluated. |
| `evaluated` | no | Every example met its expectation for this exact recipe. |
| `promoted` | yes | An operator promoted an evaluated recipe, with a reason; used while the recipe is unchanged. |
| `retired` | no | Never used again; the record and every past result are kept. Terminal. |
| `rolled-back` | no | Withdrawn after use; may be evaluated again. |

No recipe is learned from examples in this release: both shipped transformations were written by hand. "Independent" examples are held-out projects the transformation was not developed against, written by the same authors, so they are synthetic evidence of generalization, not an independent measurement.

## What this does not do

- It verifies the declared contract only. Requests, actors, objects and state checks outside the profile are not observed.
- It runs requests one at a time in one process. No concurrency is exercised, and none is claimed.
- It supports Node applications and Python WSGI applications over SQLite in this release. A Python application's WSGI callable is called directly with a real WSGI environ; no HTTP server runs. PostgreSQL is not executed (no PostgreSQL server exists on the measured host).
- Server-side request forgery and path traversal run on the Node runtime only. Outbound connections are observed at the Node connection layer (`net`, `tls`, the HTTP agents, raw sockets) and served by the declared hosts with the declared DNS answers; no socket is opened. An `https` destination is recorded and refused, never served. A connection opened below that layer (a child process, a raw binding, a native addon) is not observed, so the scope gate refuses a candidate that introduces one. A destination the declaration does not model (an undeclared name, connected to or looked up) makes the run inconclusive, never a pass.
- Password storage judges the stored value by recomputation in one approved format (scrypt as `scrypt$N$r$p$<salt hex>$<key hex>`), with cost floors: a different sound format (bcrypt, Argon2) does not hold. Timing and memory hardness are not measured. Node runtime only.
- Path traversal judges disclosure only: a planted file outside the root that reaches a response. Writes outside the root and time-of-check races are not exercised.
- Cross-execution shares only attacks that disclosed a planted secret or reached a forbidden destination; a durable-state attack is judged by the object-level check every candidate runs anyway.
- The application oracles run in the trust boundary. On Linux the boundary currently refuses to run (the namespace backend lacks proved read denial), so repair execution there is `blocked`, never a downgraded pass. The execution tests were run on macOS with the userspace backend.
- No model proposes candidates in this release. Candidates come from the shipped recipes (`sql-parameterize-template`, `path-realpath-containment`) or are supplied by a person (`--candidates`). Server-side request forgery, object authorization and password storage have no recipe.
- The challenge corpus (`bench/repair/`) is synthetic regression evidence written by the verifier's authors. It is not an independent accuracy measurement.
- A verified repair is source-only. Nothing is built, staged or deployed, and the record never says otherwise.
- An exported bundle's integrity establishes custody, not semantic correctness. Re-run the plan to re-establish evidence.
