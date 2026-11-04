# The GA programme ledger

The plan to bring every shipped capability to GA (the GA plan PRD, an untracked root working document) asks for one machine-readable ledger of acceptance records, generated into a readable status page, so that progress is read from evidence and never from a hand-written percentage. This directory is that ledger.

| File | What it is | Who writes it |
|---|---|---|
| `ledger.json` | One record per shipped registry capability: its baseline maturity, target maturity, owner role, workstreams and acceptance records; the tracked subcapabilities the PRD's GA-12 table names; and the map from every shipped surface to the capability that owns it. | People, by hand. `node scripts/ga-program/ledger.mjs --check` validates it. |
| `inventory.json` | Every shipped surface, read from the source that ships it: the CLI commands (the main dispatch switch), the report and export format sets, the MCP tools the server registers, the slash commands, hooks, agents and skills, the integration targets and ticket providers, and the distributions. Environment variables are listed and counted, not mapped. | `node scripts/ga-program/inventory.mjs --write`. Deterministic: no timestamps, no commit. |
| `STATUS.md`, `status.json` | The status page the PRD describes: baseline count, verified-GA count, promotion candidates remaining, records passed over required per capability and per workstream, the real-code accuracy with its identity, the orphan surfaces, and every reason the all-GA milestone is not met. | `node scripts/ga-program/ledger.mjs --render`. Never edited by hand. |

The registry, `docs/capabilities.yaml`, stays the only source of maturity. Nothing here promotes a capability; the ledger records a baseline maturity that must equal the registry's, and a disagreement is a finding.

## Two kinds of acceptance record

A **mechanical** record has no status in the ledger. Its status is computed when the page is rendered, from committed artifacts:

| Check | Reads | Passes when |
|---|---|---|
| `registry-ga-bar` | the registry, through the same GA-bar check the positioning gate runs | the row meets the GA bar (contract, a contract test a scanner test script runs, a release gate, platforms with a linux job, dated limits, since) |
| `evidence-identity` | `docs/scorecard.json` | the scorecard was measured on a clean worktree at the current engine version, with commit and bundle digest recorded |
| `independent-accuracy-current` | `bench/independent/RESULT.json`, `bench/independent/runs/BASELINE.json` | the independent record was measured on the current engine, names its source commit and bundle digest, and the release-tier real-code verdict is `passed` |
| `egress-all-model-paths` | the source tree | every file that sends a prompt to a model endpoint evaluates the egress policy or goes through the shared bounded call; a fetch that sends no prompt is exempt only with a reason in `program.nonModelFetch` |

A **manual** record carries the status the ledger declares, in exactly the states the PRD allows: `not-started`, `in-progress`, `blocked`, `failed`, `passed`, `not-applicable` (with a reviewed reason). A manual `passed` is counted only with a source commit, the command that produced the evidence, an evidence path that exists, and a `recordedAt` date inside the review window (`program.evidenceReviewDays`, 30 days); older evidence is reported stale and not counted. Skipped, stale, unavailable, insufficient and unmeasured are never counted as passed.

## What no session can pass

Most of the PRD is work that needs data, hardware, people or weeks: licensed real-project populations with independent adjudication (GA-02), real Haskell and Nix projects and hosted NixOS legs (GA-04), model and hardware qualification (GA-06), Linux isolation probes (GA-08), fleet and detection-product qualification runs (GA-09, GA-10), a clean-machine verifier qualification and a compliance mapping review (GA-11), pilots on five repositories and a named maintainer (GA-12). Each of those appears in the ledger as a manual record with the PRD's dependency as its blocker, and on the status page as unmet. The first status page reports 0 of 36 verified GA and says why: no capability has a current-engine independent accuracy record with identity, and every owner is a role until a person is named.

## Recording evidence

1. Run the command that produces the evidence and keep its output in the repository (a results file, a report, a test file).
2. In `ledger.json`, set the record's `status` to `passed` and fill `sourceCommit` (the full commit the evidence was produced on), `command`, `exitCode`, `evidencePath`, `recordedAt` (ISO date) and, where they apply, `artifactDigest`, `protocolDigest` and `platform`.
3. Run `node scripts/ga-program/ledger.mjs --render`, then `--check`, and commit the ledger and the regenerated page together.

## The milestone

`program.milestone.declared` is `false` until the all-current-capabilities GA milestone is claimed. The release check `ga-milestone-gate` evaluates the ledger on every release: not declared, every unmet reason is one warning, so the distance to the milestone is visible; declared, each reason is an error, and a release published with `--allow-unverified-ci` cannot claim the milestone at all. `node scripts/ga-program/ledger.mjs --milestone` prints the full list of reasons.

## Shipped surfaces

An unowned shipped surface blocks the milestone. `--check` fails on a surface the inventory finds that `ledger.json` does not map, and on a mapping whose surface no longer ships. A surface maps to a registry capability or to one of the tracked subcapabilities the PRD's GA-12 table names (distribution, harness manifests, editor plugins, the Explorer views, reports and attestations, integrations and tickets, state governance, economics and memory, the operator-only modules, and the product shell), each with its own GA-12 acceptance record under a parent capability. Where a command reaches several capabilities, the map names the primary one and notes the others.
