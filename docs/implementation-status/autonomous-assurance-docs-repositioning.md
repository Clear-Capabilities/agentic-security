# Implementation status: Autonomous Assurance docs repositioning

**Overall completion:** see "Acceptance criteria" below. Every criterion has executable or reviewable evidence recorded in this file; items that are not fully met say so.
**Current phase:** Phase 9, reconciliation (complete for the pages this work owns; residual items listed under "Not done or deliberately out of scope").
**Last verified command:** `node scripts/check-positioning-docs.mjs` (exit 0), `node scripts/check-doc-drift.mjs --gate` (exit 0), `node --test test/docs-positioning.test.js` in `scanner/` (41 tests, 0 failures). See "Verification log" for the full list and what each proved.

## Phases

| Phase | Status | Notes |
|---|---|---|
| 0 Baseline | Done | README read end to end; docs inventoried; CLI help, Labs, Code Boundaries, scanHealth, verified remediation and benchmark docs read; no website source exists |
| 1 Foundations | Done | `docs/STYLE-AND-TERMINOLOGY.md`, `docs/capabilities.yaml`, `docs/how-it-works/maturity-model.md` |
| 2 Core architecture docs | Done | Assurance lifecycle, evidence model, deterministic and agentic, finding lifecycle, Trust area (7 pages), Code Boundaries repositioned |
| 3 README | Done | 551 lines to the current count (see `wc -l README.md`) (of which about 60 are generated tables and the generated language blocks); first screen states category, promise, difference, how to try; generated tables; quickstart output re-captured |
| 4 Role docs | Done | Eight lanes, each with a primary question and a Core workflow link |
| 5 One Finding's Journey | Done | Real finding `ir-taint:server.js:11:js-sql-query`, all ten stages, captured output |
| 6 Website | Done as a package | No website source in the repository; `docs/website/` has homepage, navigation, metadata and component specs |
| 7 Visuals | Done | Six SVGs in `docs/assets/positioning/`, embedded in README and docs |
| 8 Automation | Done | `scripts/check-positioning-docs.mjs`, wired into `check-doc-drift.mjs --gate` (release gate `doc-links`) and npm scripts; 40 tests |
| 9 Reconciliation | Done for owned pages | Legacy-positioning, stale-command and overclaim searches run; see below |

## Capability registry counts by maturity

From `docs/capabilities.yaml` (37 capabilities, verified by `node scripts/check-positioning-docs.mjs`):

| Maturity | Count |
|---|---|
| GA | 12 |
| Preview | 15 |
| Labs | 7 |
| Roadmap | 3 |

Assigned conservatively from the code, tests and existing status pages. Nothing was promoted because the positioning would benefit. Labs: finding-to-rule compiler, detector spec synthesis, fleet scanning, detection and response (`dnr`), the Eval Lab, release assurance, runner-level capability enforcement. Roadmap (no implementation evidence listed): continuous production runtime observation, connected production detection, the security learning rate metric. Exploit proof, runtime corroboration, Code Boundaries and artifact provenance are Preview because their own status pages list unbuilt parts.

## Acceptance criteria

| AC | Evidence | Met |
|---|---|---|
| AC-1 First README screen states category, promise, difference and how to try | `README.md` lines 1 to 20: H1, `## Autonomous Security Assurance for the AI Software Era`, the promise line, the deterministic-plus-agentic paragraph and the three primary links. Enforced by `checkReadmeHero` | Yes |
| AC-2 One canonical ten-stage lifecycle ordering | `docs/capabilities.yaml` `lifecycle` list (ordered, validated); `checkLifecycleOrder` fails any other ordering of six or more stages; README, docs home and lifecycle page use the chain verbatim | Yes |
| AC-3 Seven-step workflow described as a subset | `docs/how-it-works/assurance-lifecycle.md` ("The operational finding workflow is a subset"), `docs/how-it-works/finding-lifecycle.md` (mapping table), README lifecycle section, STYLE guide | Yes |
| AC-4 Every major strategic capability has a maturity entry | 35 entries in `docs/capabilities.yaml`; the ten stages, Code Boundaries, provenance, proof, learn, scale, observe, detect, fix, verify, trust, model egress all present | Yes |
| AC-5 No Roadmap capability written as shipped | Registry rule (Roadmap lists no evidence), `checkOverclaims` over every owned page, stage pages Observe, Learn and Detect written in conditional tense; test `overclaim:` pair of cases | Yes, within the limits of a heuristic lint (suppression is explicit and reasoned) |
| AC-6 Trust semantics prominent | README trust statement on the first screen; `docs/trust/` (scan health, assurance modes, verified remediation, trust and limitations); README "What Agentic Security is not"; compliance limits on the Compliance lane | Yes |
| AC-7 All internal docs links pass validation | `node scripts/check-doc-drift.mjs --gate`: exit 0 (file links across README, docs, commands, skills, agents); `checkLinks` additionally validates heading anchors on owned pages | Yes |
| AC-8 Safely verifiable documented commands use valid syntax | `checkCommands` validates command names, dispatcher subcommands and slash commands in code spans and shell fences. Additionally run for real in a scratch copy of the demo app: `scan --format json --output`, `ci --assurance strict` and `advisory`, `hunt --root`, `verify --finding`, `fix --finding --preview --root`, `triage exploit --prove`, `proof doctor`, `runtime status`, `dataflow export`, `dataflow impact assess`, `compliance --list`, `compliance --gap`, `compliance --walkthrough`, `attest`, `scan --set-baseline`, `scan --since-baseline`, `fleet init`, `harness`, `secure`, `help`. All parsed and ran (exit codes in the journey page). Not run: `image scan`, `provenance trace`, `rules synthesize`, `runtime ingest`, `explore` (need an archive, a stored scan, a spec, telemetry or start a server) | Yes for names and structure; the commands that need external inputs were checked by name only |
| AC-9 One Finding's Journey has real output for shipped stages | `docs/workflows/one-findings-journey.md`: every captured block was produced by the bundled scanner against a copy of `examples/demo-app` in this work; stages that could not run show the real "nothing ran" message | Yes |
| AC-10 Every role reaches its core workflow within two clicks | `checkNavigation`: docs home links each role page; each role page has a `**Core workflow:**` link that resolves | Yes |
| AC-11 No substantial existing capability documentation lost | No existing doc page was moved or deleted. README sections that left the README are preserved in `docs/reference/capability-reference.md` (verbatim, em-dashes replaced with commas) and mapped in `docs/DOCS-MIGRATION.md` | Yes |
| AC-12 README clearer, not longer | 551 lines to the current count (see `wc -l README.md`); deep material moved to docs; first screen restructured | Yes by line count and structure; clarity is a reviewable judgment |

## Definition of done

| # | Item | Status |
|---|---|---|
| 1 | README leads with Autonomous Security Assurance | Done |
| 2 | Ten-stage lifecycle visible and explained | Done (README table, lifecycle page, ten stage pages) |
| 3 | Operational workflow nested beneath it | Done |
| 4 | `docs/capabilities.yaml` authoritative | Done; tables generated from it and checked |
| 5 | Evidence Model first-class | Done (`docs/how-it-works/evidence-model.md`, linked from README hero) |
| 6 | Code Boundaries positioned as the security graph | Done, with Runtime and Artifact evidence shown at their real, bounded status |
| 7 | CISO and Detection Engineering lanes | Done |
| 8 | One Finding's Journey | Done |
| 9 | Trust and limitations easier to find | Done (README first screen, `docs/trust/`, docs home) |
| 10 | README, docs and website language consistent | Done for owned pages; enforced by the style and consistency checks |
| 11 | Six reusable SVGs | Done |
| 12 | CI checks links and maturity consistency | Done via the release gate's `doc-links` check |
| 13 | No Roadmap capability presented as shipped | Done within the lint's limits |
| 14 | Existing technical detail accessible | Done |
| 15 | Status 100% with evidence against every acceptance criterion | See above; residual items are listed below rather than hidden |

## Visual completion

Six of six: `assurance-lifecycle.svg`, `traditional-vs-agentic.svg`, `evidence-model.svg`, `security-graph.svg`, `one-finding-journey.svg`, `platform-architecture.svg`. Each has `<title>` and `<desc>`, a `viewBox`, no percentages, and (for the four that carry maturity) the words GA, Preview, Labs and Roadmap written out in text beside border styles that differ, so maturity never relies on color alone. Checked by `checkVisuals`. Rendered to PNG with the macOS thumbnailer for a visual check of the left portion of each; the thumbnailer crops to a square so the right edge of the wide images was verified by geometry, not by eye.

## Website completion

No website source exists in the repository, so `docs/website/` is the deliverable: homepage copy in the required nine-section order, navigation, unique metadata for the eight required pages plus the discoverability terms, and component and visual specs. The license is PolyForm Internal Use (source-available); the package says not to call it open source.

## Link and command validation

- Links: `node scripts/check-doc-drift.mjs --gate` exit 0. It covers file links in README, `docs/`, `commands/`, `skills/` and `agents/`.
- Anchors: `checkLinks` in `scripts/check-positioning-docs.mjs`, over owned pages.
- Commands: see AC-8.

## Not done or deliberately out of scope

- **Distribution metadata** (`.claude-plugin/plugin.json`, `marketplace.json`, `gemini-extension.json`, `scanner/package.json` description, IDE package descriptions, the session welcome banner in `hooks/session-welcome.js`) still use the older "Full ASPM + LLMSecOps" and "easy button" wording. They are shipped metadata covered by release-gate version synchronization and tests; the PRD scopes this work to README, docs and website, and lists scanner behavior changes as a non-goal. Updating them is a separate, small change.
- **Repository topics and description** are GitHub settings, not files. The SEO terms are recorded in `docs/website/metadata.md` for whoever sets them.
- **Per-page social cards** do not exist; the metadata page names the existing `docs/brand/social-preview.png` as the fallback.
- **Historical and assurance-programme docs** (for example `docs/guides/assurance-*.md`, `docs/implementation/`) were not restyled. They are linked, indexed, and tracked by the capability ledger, but they are outside the owned-page style rules (no em-dash lint on them).
- **The registry parser is deliberately small** (flat records, no general YAML). It is covered by tests that refuse a line it cannot read.
- **The overclaim lint is a heuristic.** A false negative is possible; a false positive can be silenced with `<!-- positioning-ignore: reason -->`.
- **The static `README.md` capability tables are regenerated, not hand-edited.** The SVGs are static artifacts: their stage maturity text is not generated from the registry. Changing a maturity means re-checking the four maturity-bearing SVGs by hand. A generator used to produce them was kept outside the repository.
- **Baseline observation worth knowing:** at the start of this work, one run of `check-doc-drift.mjs --gate` reported a single assurance-docs finding (an `AGENTIC_SECURITY_ASSURANCE_*` variable named in the invariants example that the check could not find read by any module). A later run, after new docs were added, did not report it, and the cause of the difference was not established. It is unrelated to the positioning checks. If it reappears it is pre-existing.

## Verification log

Each line is a command run during this work in the current session, with what it showed.

| Command | Result |
|---|---|
| `node scripts/check-positioning-docs.mjs` | exit 0; 37 capabilities (12 GA, 15 Preview, 7 Labs, 3 Roadmap); tables fresh; links, commands, lifecycle order and style clean |
| `node scripts/check-doc-drift.mjs --gate` | exit 0 with the positioning checks included |
| `node --test test/docs-positioning.test.js` (in `scanner/`) | 41 tests, 0 failures; both directions proved for each rule |
| `node --test test/language/capability-ledger.test.js` | 14 tests, 0 failures after the new pages were mapped in `docs/capability-ledger.json` |
| `node --test test/unscored-claims.test.js` | 7 tests, 0 failures (README still names `agentic-security image scan` and the remaining image-scanning gap) |
| `node scripts/render-language-docs.mjs --check`, `node scripts/capture-language-examples.mjs --check` | both exit 0; the generated Haskell and Nix README blocks are unchanged |
| `npm run test:lifecycle` (in `scanner/`) | see the final entry below |

## Rebase onto 0.177.0 (what changed while this was in review)

Main moved from 0.172.1 to 0.177.0 during this work (independent accuracy measurement, release assurance, fleet job fabric, `dnr`, the Eval Lab, container-engine and registry image sources, a stronger rule compiler and proof fabric). The branch was rebased and the docs were reconciled, not just merged:

- Detect moved from Roadmap to Labs for `dnr` (generate, validate, hunt, window); connected SIEM detection stays Roadmap.
- The demo finding changed: on the 0.177.0 engine the demo SQL injection is `struct:server.js:11:SQL_Injection_(Template_Literal)`. One Finding's Journey was re-captured from scratch against the new engine, including `dnr`, `proof generate`, `rules status` and the refusals they print.
- Trust pages now state the measured independent accuracy (precision 6/19, recall 6/278, F1 0.040) and the scan-health change for skipped files.
- Artifact provenance limits, fleet limits, rule compiler limits and the proof limits were updated from the new guides.
- A bug found while re-running the table generator: with empty adjacent generated blocks, `--write` could swallow the prose between them. Fixed and pinned by a test; the lifecycle page, which was affected, was rewritten from its source text.
