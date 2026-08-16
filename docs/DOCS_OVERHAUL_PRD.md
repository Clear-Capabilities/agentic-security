# PRD: World-Class Docs & README

**Status:** Implemented in 0.137.0 (P0–P3 all landed; see CHANGELOG)
**Owner:** Ross Young
**Created:** 2026-08-15
**Design approved:** 2026-08-15 (brainstorm session; approach A of three)

---

## 1. Problem

The product has a strong **evidence layer** (ARCHITECTURE.md, METRICS.md, SCORECARD.md,
compliance coverage maps, AGENT_THREAT_MODEL.md) and **zero learning layer**. A
documentation survey (2026-08-15) found:

- **No quickstart, tutorial, or walkthrough exists anywhere in the repo.** The
  README's Install section drops a new user at a command list with no narrative
  next step.
- **The de-facto user manual is `commands/*.md` — agent prompts.** Critical
  user-facing facts live only there: exit-code semantics (0–4 are verdicts, not
  errors) appear exclusively inside `commands/scan.md`; the SBOM how-to is a JSON
  shape spec addressed to Claude; the best onboarding artifact in the repo (the
  "I want to… → Command" table) is buried in `commands/secure.md`.
- **Core tasks have no how-to documentation:** first scan, triage → fix loop,
  SBOM / AI-BOM generation, secrets rotation, CI setup (beyond one GitHub-only
  example file), configuration and env-var reference. "AI-BOM" appears exactly
  once in all of docs/ — inside an architecture diagram.
- **Several doc claims are false or self-contradictory** (§4, P0 below).

Why it matters: open-source tools that both go viral and land in large
enterprises follow a bottom-up motion — one engineer reaches a "wow" in
minutes, champions the tool internally, then the security team evaluates the
depth layer. We have the depth layer. We are missing the five-minute wow and
the task-oriented middle. This PRD adds the missing layers and fixes what's
false, without moving any existing file.

## 2. Goals

1. A brand-new user reaches their **first real finding in under 5 minutes**,
   guided, with guaranteed-reproducible output.
2. Every core job — scan, fix, SBOM/AI-BOM, compliance, CI, leaked-secret
   response — has a **task-oriented guide** reachable in **≤ 2 clicks from the
   README**.
3. An enterprise evaluator finds the **evidence layer in one click** (docs hub
   lane), organized rather than scattered.
4. **Every command shown in a guide is copy-paste runnable** against the demo
   app or an obvious substitute. No aspirational docs.
5. **Doc rot becomes mechanically impossible** for the failure classes we've
   already observed: dangling internal links and manifest version drift fail
   the release gate.

**Non-goals:** a hosted docs site (possible later phase, out of scope); moving
or renaming existing docs (churn without user value; breaks inbound links);
rewriting `commands/*.md` dispatchers (they are agent prompts and stay that
way — user docs will *duplicate the user-facing facts*, not point users at
prompts); localization; video content.

## 3. Audience model

**Vibecoder-first in sequence, not in scope.** The quickstart and guides
assume zero security knowledge (that is the viral loop). The evidence layer
serves the security professional the champion brings in later. Docs are
layered so each reader exits at their depth:

| Reader | Entry | Path |
|---|---|---|
| New user ("is this for me?") | README | value prop → Quickstart in ≤ 5 min |
| Returning user ("how do I X?") | docs hub / README Docs section | one guide per task |
| Security team ("can we trust it?") | docs hub, Evaluating lane | ARCHITECTURE, METRICS, SCORECARD, compliance maps, threat model |
| Contributor | docs hub, Contributing lane | CLAUDE.md tree, ROADMAP, internal PRDs |

## 4. Deliverables

### P0 — Accuracy pass (truth before polish; ships first)

Every item below was found by the survey; each fix starts by **re-verifying
the claim against the code in the current tree** (never trust the survey
blindly — verification discipline applies to docs too):

| # | Issue | Fix |
|---|---|---|
| 0.1 | `gemini-extension.json` declares version `0.75.1` (~60 minor versions behind); two other manifests disagree with each other during normal release flow | Sync to the current release version; add a **manifest version-sync check** so this class of drift fails the release gate (see 0.8) |
| 0.2 | `docs/MODEL_COST_OPTIMIZATION.md` says "ships **on** (`mode: "advise"`) by default" and, twelve lines later, "`off` *(default)*" | Read `hooks/model-cost-advisor.js`, determine the real default, make the doc say one true thing |
| 0.3 | `commands/compliance.md` Modes-table row for `--gap` promises "the exact command that closes it"; the `--gap` section below explicitly retracts that claim | Fix the table row to match reality |
| 0.4 | `skills/security-rotate-leak/SKILL.md` references `commands/rotate-key-auto.md`, deleted in v0.86.0 | Repoint to the live equivalent (`/fix --rotate-secret` path) or inline the provider matrix |
| 0.5 | README lists `hunt` under commands introduced by "Every command is invoked as `/agentic-security:<name>`" — but `hunt` is CLI-only (no `commands/hunt.md`) | Reword so `hunt`'s CLI-only nature is explicit |
| 0.6 | `commands/secure.md` documents `--tour` / `--daily` modes; no implementation was found under `scanner/src/` | Verify: if implemented (possibly agent-side), keep and note where; if not, remove from docs or implement a minimal deterministic version — **never document behavior we can't demonstrate** |
| 0.7 | README version badge is hardcoded and already stale (`0.136.10` after the `0.137.0` release) | Update; include the badge in the version-sync check (0.8) so it can't silently rot again |
| 0.8 | No mechanical guard against doc rot | Extend `scripts/check-doc-drift.mjs`: (a) **dangling internal links** — every relative `.md`/file link in README.md and docs/**.md resolves to an existing file; (b) **manifest version sync** — `scanner/package.json`, `.claude-plugin/plugin.json`, `gemini-extension.json`, and the README version badge agree. Wire into the release gate the same way the existing drift checks run |

### P1 — Demo app + quickstart + README (the viral core)

**`examples/demo-app/`** — a small, deliberately vulnerable app every tutorial
scans, so screenshots and expected output are reproducible:

- Node/Express + a Dockerfile + a small Python file, ~10 short files total.
- Target findings (~8, spanning the pillars so every guide can point at it):
  SQL injection via string concat (SAST + taint), hardcoded API key (secrets),
  a known-vulnerable dependency pin (SCA → SBOM/CVE story), Dockerfile
  running as root (IaC), user input flowing into an LLM prompt
  (LLM safety → AI-BOM story), missing auth on a state-changing route (authZ),
  `eval` on user input (bodyguard demo), weak hash for passwords (deterministic
  zero-LLM fix demo — instant fix gratification in the quickstart).
- A short README inside the app stating loudly that it is intentionally
  vulnerable, never to be deployed, and listing what each file demonstrates.
- **Gate constraint (must-solve):** this repo self-scans
  (`npm run bench:self-scan:check`) and its pre-push gate would fail with a
  vulnerable app in-tree. The demo app must be excluded via the self-scan
  harness's ignore mechanism — explicit, commented, and **narrow** (the
  exclusion covers `examples/demo-app/` only). Acceptance: self-scan gate
  passes with the app present; scanning the app directly still yields the
  expected findings; the corpus/mutation gates are untouched.
- The demo app's expected findings are **pinned by a test** (a lightweight
  fixture-style check: scanning `examples/demo-app` produces ≥ the expected
  finding families), so a detector change that would break the quickstart's
  promised output fails CI instead of breaking the tutorial silently.

**`docs/guides/quickstart.md`** — "Your first 15 minutes":

1. Install — both paths (Claude Code plugin; bare `npx`), with the real
   two-command marketplace sequence.
2. Scan the demo app — one command; show the actual verdict block the user
   will see.
3. Read the output — severity, dollar-cost estimate, KEV/EPSS line, what
   "Not safe to deploy" means, exit codes.
4. Fix one finding — the weak-hash deterministic fix: run it, watch the
   verify gate (rescan-clean + no new ≥ medium + lint) pass, see the diff.
5. Export the HTML report — `--format html`, open it, note it's shareable.
6. "Now your own project" — `/secure` or `npx … secure .`, plus
   `--set-baseline` for legacy codebases so day-one output isn't a wall.

Tone rules for the quickstart (and all guides): plain English, no CWE/CVE
jargon in the main path, every code block copy-paste runnable, expected output
shown after every command, no external tool names (project rule).

**README updates** (landing page, not manual):

- New **Quickstart** section directly after Install: the demo-app one-liner,
  expected-output teaser, link to the full tutorial.
- New **Docs** section: the four-lane table (New here / Doing a task /
  Evaluating / Contributing) linking to the hub and top guides.
- The P0 factual fixes (0.5, 0.7) land here too.
- Nothing removed; net growth ≤ ~40 lines — task content lives in guides.

### P2 — Six how-to guides (`docs/guides/`)

Common format per guide: *Goal* (one sentence) → *Prerequisites* →
*Steps with expected output* → *Variations* → *Troubleshooting* → *Related*.
Both invocation styles shown throughout (Claude Code `/agentic-security:<cmd>`
and bare CLI `npx @clear-capabilities/agentic-security-scanner <cmd>`).

| Guide | Covers | Key facts being rescued from agent prompts |
|---|---|---|
| `scanning.md` | full / diff / watch / baseline / archaeology modes; reading findings; HTML/JSON/MD/SARIF/CSV export; suppression pragma; `--include-suppressed` | Exit codes 0–4 as verdicts (today only in `commands/scan.md`) |
| `fixing-vulnerabilities.md` | triage (show/explain/validate) → fix loop; `/fix --all` parallel semantics; the verification gate; completeness tiers (FULL/MITIGATION/WORKAROUND); revert path | Fix acceptance-rate reporting; regression tests shipping with fixes |
| `sbom-and-ai-bom.md` | `/supply --sbom` (SBOM), AI-BOM generation, license policy, `--cve-alerts`, reachability tiers and what to fix first | The SBOM JSON-shape knowledge in `commands/supply.md`, rewritten for humans |
| `compliance.md` | choosing a framework; `--report` vs `--walkthrough` vs `--gap`; the four honesty buckets (gap / not-assessed / manual / satisfied) and why governance controls are never auto-passed; privacy framework opt-in; custom controls | Bucket model from `commands/compliance.md`; exit-code semantics (0/1/2) |
| `ci-setup.md` | `/setup --ci` across all 5 providers; the committed GitHub example; `--predeploy` deploy gate; baseline-then-gate workflow for legacy repos; PR-comment output | Provider matrix from `commands/setup.md`; `docs/examples/security.yml.example` gets linked, not duplicated |
| `leaked-secrets.md` | incident response: detect → don't-echo rule → identify provider → revoke/rotate (`/fix --rotate-secret`) → scrub history → verify | The 6-step sequence currently trapped in `skills/security-rotate-leak/SKILL.md` |

`docs/MODEL_COST_OPTIMIZATION.md` already is a good task doc — it gets linked
from the hub, not rewritten.

### P3 — Reference pages + hub

- **`docs/reference/cli.md`** — every CLI subcommand with flags, arguments,
  exit codes, and output formats. Source of truth is the code
  (`scanner/bin/agentic-security.js` + dispatchers); every flag documented is
  verified by running `--help` or the subcommand.
- **`docs/reference/configuration.md`** — one page for what is today scattered
  across ≥ 4 docs: all `AGENTIC_SECURITY_*` env vars (a table: name, effect,
  default); every `.agentic-security/` file (what writes it, what reads it,
  whether it's signed); `rules.yml` (custom rules, severity overrides,
  gated `disable:`, shadow mode); the suppression pragma and its line-scope
  rule; config precedence.
- **`docs/README.md`** — the navigation hub. Four lanes (audience model
  above), one screen, mostly links with one-line descriptions. Existing
  evidence docs get organized here without moving.

## 5. Constraints & principles

- **No external tool names anywhere in shipped docs** (project rule — applies
  to guides, demo app comments, and the PRD's own examples).
- **Verification discipline applies to docs:** a claim about behavior requires
  having run the command in the current tree. Guides are written *after*
  running each step against the demo app, pasting real output.
- **Existing files don't move.** The hub organizes; it does not relocate.
- **`commands/*.md` remain agent prompts.** Guides duplicate user-facing facts
  deliberately; the doc-drift checker (0.8) is the rot backstop.
- **License posture unchanged** — docs encourage internal sharing and use;
  no wording that suggests repackaging/resale is permitted.

## 6. Success criteria (acceptance)

1. Fresh-clone test: following quickstart.md verbatim on a machine with only
   Node 24 yields the promised findings and one applied fix in ≤ 15 minutes;
   the first finding appears in ≤ 5.
2. Every fenced command in every guide runs successfully against the stated
   target (demo app or repo) at the commit that ships it.
3. `node scripts/check-doc-drift.mjs` (extended) passes and demonstrably
   fails when (a) a doc link is broken, (b) a manifest version is desynced —
   both directions proven once during P0.
4. All existing gates stay green with the demo app in-tree: full test suite,
   self-scan baseline, CVE-replay corpus, mutation gate.
5. Each of the six core tasks reachable from README in ≤ 2 clicks.
6. Zero occurrences of external tool names in new content (`grep` sweep).

## 7. Sequencing

P0 → P1 → P2 → P3, single branch, committed per phase. P0 ships first because
polishing docs that contain false claims is lipstick; P1 is the highest-value
new content (the wow); P2 the task middle; P3 the long-tail reference. Each
phase ends with the doc-drift checker and affected gates green.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Demo app breaks self-scan / pre-push gates | Explicit narrow exclusion, added in the same commit as the app; gate run proven both directions |
| Demo app findings drift as detectors evolve → quickstart lies | Expected-findings test pins the contract (P1) |
| Guides drift from CLI reality over time | Doc-drift checker catches links/versions; guide commands are also exercised by the demo-app test where feasible; residual risk accepted and reviewed at release time via the existing scorecard flow |
| A "vulnerable demo app" alarms a security-conscious evaluator | Loud in-app README; no deployable surface (no real keys, no network calls beyond localhost); standard practice for security-tool education |
| README bloat | Hard cap: net ≤ ~40 added lines; everything else lives in guides |
