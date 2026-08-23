# agentic-security

Full ASPM + LLMSecOps Claude Code plugin. Delivers SAST, SCA (OSV + CISA KEV + function-level reachability), secrets, IaC, prompt-injection, MCP/agent-tool audit, auth/authZ deep analysis, attack chains, PoC generation, SBOM/PBOM/AI-BOM, and compliance attestation (NIST AI 600-1, NIST Privacy Framework 1.1, OWASP ASVS, OWASP LLM Top 10, EU AI Act).

**Version:** 0.141.0  
**License:** PolyForm Internal Use 1.0.0  
**Author:** Ross Young <ross@clearcapabilities.com> / Clear Capabilities Inc.

**ICP focus:** vibecoder-first; pro is follow-on. See `docs/POSITIONING.md` for the in/out call.

---

## Repository layout

| Path | Purpose | Local CLAUDE.md? |
|------|---------|------------------|
| `scanner/` | Node.js scan engine (ESM, Node ≥ 24). Bundle at `dist/agentic-security.mjs`. | `scanner/CLAUDE.md` |
| `scanner/src/sast/` | SAST detector modules. 60+ files. Adding a rule? Read here. | `scanner/src/sast/CLAUDE.md` |
| `scanner/src/posture/` | Annotation pipeline + state stores. 90+ modules. | `scanner/src/posture/CLAUDE.md` |
| `scanner/src/dataflow/` | Layer-2 taint engine (k=1 monovariant return-taint; see local file for what is and isn't modelled). | `scanner/src/dataflow/CLAUDE.md` |
| `scanner/src/discovery/` | LLM candidate discovery, gated by the deterministic engine. Propose → confirm → refute → judge. | `scanner/src/discovery/CLAUDE.md` |
| `scanner/src/mcp/` | MCP server. 17 tools (2 write: `apply_fix`, `apply_sca_upgrade`); OWASP MCP Top 10 hardened. | `scanner/src/mcp/CLAUDE.md` |
| `scanner/src/ir/` | Layer-1 IR: Babel-based JS/TS; Python via stdlib `ast` subprocess (default, when python3 available) with regex fallback; `java-parser`-based Java. | `scanner/src/ir/CLAUDE.md` |
| `scanner/src/lsp/` | LSP server wrapping `runScan`. Ships with the JetBrains + Neovim plugins. |  |
| `scanner/src/llm-validator/` | Layer-3 LLM validator. **Default-on whenever `AGENTIC_SECURITY_LLM_ENDPOINT` is configured** — not gated on a separate opt-in flag. Opt out with `AGENTIC_SECURITY_LLM_VALIDATE=0`. With no endpoint configured it stays a no-op regardless, so an unrelated env var can never trigger a surprise network call. |  |
| `scanner/test/` | Node test runner suite. Scoped via `npm run test:{smoke,sast,posture,dataflow,mcp,report,lifecycle}` — see `scanner/CLAUDE.md`. |  |
| `bench/cve-replay/` | Real-CVE replay corpus + runner. 210 entries (3 regression + 201 capability + 6 deep), all `pre:TP post:TN`; target 500. Execution-proven findings can auto-enrol via `npm run corpus:enroll` — see `scanner/src/posture/CLAUDE.md`. Baseline-gated via `npm run bench:cve-replay:check` (`bench/cve-replay/CONTRIBUTING.md`). |  |
| `bench/layer-recall/` | Per-layer, per-language recall (`npm run bench:layer-recall:check`). Answers *which analysis layer* detected each corpus entry, with deep mode forced on for all 210. Baseline-gated on per-language taint counts. Published at `docs/METRICS.md`. As of 2026-08-19 taint attributes **116/215 (54%)** and every first-class language is non-zero (kotlin, the last at 0%, is now 48%); only `json` and `terraform` are at zero, correctly — neither is code the taint engine can walk. java, ruby, and c# were each fixed from 0% after real IR-layer defects were found. **The gate is a FLOOR, not an equality check** — it fails on a drop and is silent on a rise, so the engine improving 31 → 116 passed it without comment and left the published table stale for weeks. Re-baseline deliberately after taint work; do not read a passing gate as "the numbers are current." |  |
| `bench/mutation/` | Metamorphic + adversarial mutation gate (`npm run bench:mutation:check`). Scores **verdict-flip correctness**, not detection count: a semantics-preserving rewrite must not move the verdict, a semantics-changing near-miss must. This is the anti-overfitting check — accumulating patterns cannot raise the score, and an engine that games a family check fails it. Each case declares a `dimension`: `sanitization` (does the engine label the flow sanitized) or `detection` (does the finding fire at all — needed for gates like R6's receiver-type check, where there is no sanitizer to have an opinion about). Both still score verdict-flip, never count. |  |
| `bench/owasp-benchmark-v1.2/`, `bench/sard-juliet-java/`, `bench/polyglot/` | External benches (gitignored, regenerated). |  |
| `commands/` | Slash-command markdown files. 10 dispatchers: `secure`, `find-and-fix-everything`, `scan`, `triage`, `fix`, `posture`, `compliance`, `supply`, `setup`, `labs`. Every capability is a mode of a dispatcher (e.g. CI gates live at `/setup --ci`, the red/blue/auditor deep-dive at `/triage --deep`); the legacy single-purpose aliases redirect via `hooks/legacy-alias-redirect.js`. |  |
| `agents/` | Sub-agent system prompts. Edit-capable agents follow `agents/_CONFINEMENT.md`. |  |
| `hooks/` | Claude Code hook scripts + `hooks.json`. |  |
| `.githooks/` | Committed **git** hooks (distinct from `hooks/` above, which is editor integration). Currently `pre-push`, a shim over `scripts/pre-push-gate.mjs`. Activated per clone via `core.hooksPath` — see "Pre-push gate". |  |
| `scripts/` | Compliance + helper scripts + CI templates (`scripts/ci-templates/`). |  |
| `docs/standards/` | Upstream standards source material. A document lives here **only if a generator reads it** — currently just `NIST AI 600-1.xlsx`, consumed by `scripts/nist-compliance/build-catalog.py`. Never read at runtime. | `docs/standards/README.md` |
| `docs/compliance/` | Per-framework coverage maps, derived from the framework JSON. One per framework linked in the README table. |  |
| `docs/POSITIONING.md` | ICP statement: vibecoder-first; pro follow-on. |  |
| `docs/HARNESS_ASSESSMENT_SPEC.md` | Six-domain rubric for scoring an AI agent harness (PRD-derived, versioned). |  |
| `docs/HARNESS_ASSESSMENT_EVIDENCE.md` + `docs/schemas/harness-evidence.schema.json` | Wire format a conforming harness must emit so it can be scored. |  |
| `ide/{jetbrains,nvim,vscode}/` | IDE distributions. |  |
| `.claude-plugin/` | Plugin manifest (`plugin.json`, `marketplace.json`). |  |
| `.claude/settings.json` | Team-committed Claude Code settings (read-deny rules for bundles + cached artifacts). |  |
| `.agentic-security/` | Runtime state (last scan, streak, rules override, hook throttle). |  |

---

## Build & test

```bash
cd scanner/
npm install
npm run build          # bundles dist/agentic-security.mjs via @vercel/ncc; emits a SHA-256 sidecar
npm test               # full CI gate (chains the scoped scripts below)
npm run test:smoke     # one-file fixture, fast
npm run test:sast      # SAST detector tests
npm run test:dataflow  # IR + taint engine + calibration + held-out eval
npm run test:mcp       # MCP server + audit log
npm run smoke          # bundle smoke: CLI vs vulnerable-js fixture
```

All scoped scripts are defined in `scanner/package.json`. Pick the one closest to what you touched; `scanner/CLAUDE.md` documents which test files are in which scope.

After any change to `scanner/src/` or `scanner/bin/`, run `npm run build` before relying on the bundle. Unit tests run against `src/` directly and do not require a rebuild.

### Pre-push gate

`git push` is gated locally so broken code cannot reach the remote and be discovered afterwards by hosted CI. `.githooks/pre-push` is a committed shim over `scripts/pre-push-gate.mjs` (`npm run gate:prepush` in `scanner/`).

- **Activation.** `core.hooksPath` is per-clone local config, so a fresh clone starts ungated. `npm install` in `scanner/` activates it — the `prepare` script runs `node ../scripts/pre-push-gate.mjs --install-hook`, which sets `git config core.hooksPath .githooks` and prints a one-line confirmation. To do it by hand: `git config core.hooksPath .githooks`. If someone never runs the setup step, **nothing gates their pushes**; the gate prints a loud WARNING whenever it notices it is running in a clone where `core.hooksPath` is not `.githooks`.
- **What it runs**, in cheapest-fail-first order, stopping at the first failure: bundle vs its SHA-256 sidecar (in-process, fails in well under a second — this is what catches "edited `src/`, forgot to rebuild"), then `npm test`, `npm run bench:cve-replay:check`, `npm run bench:self-scan:check`.
- **Cost:** roughly 2.5–3.5 min for a full pass (measured 201 s on the maintainer's machine); a failure at the bundle check costs 0 s and a failing test aborts in ~20 s.
- **Scope.** Refs come from the hook's stdin. A ref deletion and a ref with no new commits are not gated; a brand-new branch is.
- **Bypass:** `git push --no-verify` skips every hook. That cannot be prevented and is the intended escape hatch. On success the gate prints one `pre-push gate PASSED` line, so its *absence* from a push's output is the visible sign it was bypassed.
- **Deliberately excluded:** the network-dependent checks — dependency currency and hosted-CI status. They are slow, they describe the state of the world rather than the code, and an offline developer must still be able to push. They run at publish time via `npm run release:check` (`prepublishOnly`), which remains the full set.
- An unrunnable check (missing script, spawn failure) is a **FAILURE**, never a skip.

### Signed, portable evidence (PRD D2)

Run attestation (posture/attestation.js) is a per-install SYMMETRIC HMAC — tamper-evidence for the operator, not third-party non-repudiation. posture/evidence-bundle.js is the other half: an Ed25519-signed bundle per FINDING, verifiable by someone who has only the public key.

- agentic-security attest [--id <finding>] — writes signed bundles to .agentic-security/attestations/
- agentic-security verify-attestation <bundle.json> --public-key <path> — exits 0 valid, 1 invalid

A bundle PROVES its contents are unmodified since signing. It does NOT prove the finding is real — both statements are carried inside the bundle and are covered by the signature, so neither can be dropped or softened in transit. The attack it defeats is silently promoting an unproven finding to execution-proven.

### Two publish paths, and only one carries provenance

- **Tag a release (preferred).** Push a `vX.Y.Z` tag. `.github/workflows/release.yml` runs the full gate with `--no-cache` on a clean runner and publishes with `npm publish --provenance`, so the artifact carries a verifiable link back to this repository and commit. Needs the `NPM_TOKEN` repository secret.
- **Local `npm publish`.** Still supported and still fully gated by `prepublishOnly`. It produces **no provenance attestation** — npm requires a trusted CI publisher with OIDC for that. Use it when you must; prefer the tag.

`workflow_dispatch` on the release workflow runs the gate and `npm pack --dry-run` without publishing, which is the cheapest way to check a release would go out cleanly.

When cutting a release, run `npm run scorecard` (regenerates `docs/SCORECARD.md` + `docs/scorecard.json`), review the numbers, and commit the result — `scripts/release-check.mjs`'s `scorecard-freshness` check enforces this at publish time (wired into `prepublishOnly` and `release.yml`) by failing when the committed scorecard's `engineVersion` doesn't match `scanner/package.json`'s version, or when its `corpus.totalEntries` disagrees with the corpus actually on disk; it checks, it does not regenerate. `npm run scorecard:check` runs the same underlying decision logic (`scorecard-check.mjs`) standalone for local iteration, but is not itself wired into any gate — `release-check.mjs` imports the logic directly rather than shelling out to it.

---

## Verification discipline (read before you claim anything works)

Several releases (v0.106.0–v0.107.1) shipped broken or false because work was **reported as done without confirming the artifact actually changed**. The pattern was always the same: an edit silently failed, or a status file was stale, and the next step trusted the *intent* instead of the *result*. These rules exist to make that impossible. They override any urge to move fast.

- **Confirm every mutation landed — don't assume.** An `Edit` whose `old_string` doesn't match returns "String not found" and changes nothing; a `node -e` that rewrites JSON can drop sibling keys. After any edit to a file you're about to rely on, re-read the specific region or `grep` for the exact thing you added. "I edited it" is not "it changed."
- **Read the actual command output, never a cached or `/tmp` summary.** Benchmarks, test runs, and gates must be judged from the run you just executed in this turn. A `/tmp/*.txt` from three steps ago is stale the moment anything changed. When output is long or the terminal is noisy, write it to a file and `Read` that file — but only one you wrote *this turn*.
- **A claim about a number requires the run that produced it.** Never state a corpus F1, test pass count, or coverage figure unless it came from a command in the current turn. If you didn't just run it, say "not re-verified," don't quote the last number you remember.
- **Capture exit codes for anything that gates.** A gate that "looks like it ran" is worthless. Run it, capture `$?`, and prove BOTH directions: it exits 0 on the good input AND non-zero on a deliberately bad one. An unknown CLI flag or a missing npm script exits without enforcing — verify the script/flag exists by running it, not by reading the file that *should* define it.
- **Pre-flight before commit/push.** Before `git commit`: `git status`/`git diff --cached --name-only` must match exactly what you intended (no missing new files, no stray `.agentic-security/` state, version bumped in all files). Before `git push`: re-run the full gate (`npm test`) and the corpus gate (`npm run bench:cve-replay:check`) and read both results. A green local gate is the price of pushing — there is no "probably fine."
- **The corpus is gated; respect it.** `bench/cve-replay/corpus-baseline.json` records the expected verdict for every entry. Adding or changing entries means `npm run bench:cve-replay:check` (fails on any drift) then `npm run bench:cve-replay:update-baseline` and committing the regenerated baseline. Never add a corpus entry without confirming it scores `pre:TP post:TN` — an undetectable fixture is the exact mistake the gate now catches.
- **Wipe scan state before benchmarking.** `.agentic-security/` dirs accumulate inside scanned `pre/`/`post/` trees and can mask results. `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +` before generating or checking a baseline so it reflects a clean tree.
- **Report failures as failures.** If a step errored, was skipped, or you couldn't verify it, say so plainly with the evidence — don't paper over it with a confident summary. A correct "this is broken" is worth more than a false "this is done," and the latter has cost this project real rework.

---

## Key conventions (the things you'll get wrong without reading them)

- **ESM throughout.** All `scanner/src/` files use `import`/`export`. No CommonJS in the scanner tree.
- **No runtime cloud calls.** OSV/KEV/EPSS data is fetched lazily and disk-cached under `~/.claude/agentic-security/osv-cache/`. New network dependencies must be opt-in and degrade gracefully when offline.
- **Findings schema.** Every finding must include `{ id, severity, file, line, vuln, cwe, description, remediation, parser, family }`. Severity values: `critical`, `high`, `medium`, `low`, `info`. Phase-1 extends with `stableId`, `confidence` + `confidenceTier`, `exploitability` + `exploitabilityTier` + `exploitabilityFactors[]`, optionally `clusterSize` / `exampleFlows[]`, and `unreachable:true` for reachability-demoted. `parser` + `family` are required — `posture/finding-defaults.js` backfills, but detector-set values win.
- **Suppression pragma.** `// agentic-security-ignore: <rule-id>` on the offending line (`#` and `/* */` forms work too). **Line-scoped**, matched against the finding's id, vuln, CWE or family; a bare pragma with no rule id suppresses every finding on that line. Every suppression is written to the same ledger custom rules use, so `--include-suppressed` and the suppression summary show it — a suppression nobody can see is indistinguishable from a finding that never fired. Implemented in `engine.js` (`_applyIgnorePragmas`), which runs **twice**: once after dedupe and the cross-file passes, and again after deep-mode IR findings are appended. The second pass is not optional — deep-mode findings land hundreds of lines after the first one, so before it existed an `agentic-security-ignore` on an `ir-taint` finding was inert, silently, in the mode the CLI actually uses outside CI. **A finding with no integer `line` can never be suppressed** (`struct:` detectors emit these — the line survives only inside the id string); a file-scoped fallback was deliberately rejected, because silently widening a line pragma to a whole file would suppress findings nobody looked at. Fix those at the source instead. It was documented and advertised for a long time before anything implemented it; `test/ignore-pragma.test.js` pins both the ordinary and the deep-mode path in both directions, and the line-less gap is documented-but-untested (see the note at the end of that file).
- **Rules override is gated.** `.agentic-security/rules.yml` `disable:` entries take effect only when a sibling `.sig` verifies under the per-install HMAC key, or `AGENTIC_SECURITY_RULES_UNSIGNED=1` is set. `severityOverrides`, `custom:`, and `ignorePaths` are not gated (they don't reduce coverage).
- **last-scan.json integrity.** Each write is accompanied by a `.sig` (HMAC-SHA256). The key is per-install (32 random bytes at `$XDG_CONFIG_HOME/agentic-security/scan-key`, mode 0600) — NOT the hostname. Override via `$AGENTIC_SECURITY_HMAC_KEY` (hex).
- **Calibration is held-out-only.** The seed corpus is for *fitting* the calibration table; never compute Brier/ECE against the same labels. Use `posture/holdout-eval.js` with a separate JSONL.
- **Bench-shape isolation.** Answer-key reading (Juliet folder names, OWASP template markers) lives under `sast/bench-shape/` and is OFF by default. `AGENTIC_SECURITY_BENCH_SHAPE=1` enables; `AGENTIC_SECURITY_BLIND_BENCH=1` overrides to force off.
- **Shadow mode.** Custom rules with `shadow: true` write to `.agentic-security/shadow-findings.json` and are excluded from CI gates — for experimental rules not yet ready to block.
- **Test fixtures.** New rules need a minimal `vulnerable/` + `clean/` pair under `scanner/test/fixtures/<rule-name>/`. Smoke must detect in `vulnerable/`, must pass on `clean/`.
- **Sub-agent model/effort override (interactive cost advisor).** If `.agentic-security/model-optimizer-state.json` has a `subagentOverride: {model, effort, setAt}` for the *current* session (not a stale one from a prior session — it's cleared at every `SessionStart`), apply that `model`/`effort` when dispatching cost-sensitive, delegable Agent/Task subagent calls — **unless** the specific subagent already pins its own `model:` in its frontmatter (e.g. `agents/security-triager.md`, `agents/sca-triager.md` — always respect a static pin over the override), or the task clearly needs more capability than the override provides (the override is a cost preference, not a ceiling on judgment). This override only exists when the user explicitly opted into `interactive: true` (see `hooks/model-cost-advisor.js`'s header comment and `docs/MODEL_COST_OPTIMIZATION.md`) and then chose it via an `AskUserQuestion` prompt raised by that hook's `additionalContext` directive — if you see that directive, follow it (call `AskUserQuestion`, then persist the answer to the same state file yourself, per the directive's exact instructions) rather than silently ignoring it.

---

## Dependency currency + the hold list

Release gate check `dependency-currency` (`scripts/dependency-currency.mjs`, listed by id rather than position — the checks array has grown twice since this paragraph was first written and a hardcoded ordinal drifted stale both times) keeps both package trees — `scanner/` and `ide/vscode/` — free of known-vulnerable and stale dependencies. It has two halves, and they are deliberately unequal:

- **Known advisories — no opt-out.** Any advisory at **moderate severity or above**, in either tree, fails the gate. There is no flag, no hold, no waiver. A dependency with a published vulnerability is never an acceptable release state.
- **Outdated dependencies — holdable.** Anything behind its latest published version fails *unless* it is listed in `.dependency-holds.json` at the repo root. Each entry carries `package`, `tree`, `heldAt`, `reason`, `addedAt`, `reviewBy`. The list exists because "always latest" is occasionally wrong: `web-tree-sitter` is pinned at `0.20.8` because the newer runtime cannot load any grammar in the newest published prebuilt bundle (older grammar ABI), silently dropping six long-tail languages — see `scanner/src/ir/tree-sitter-loader.js`.

Three anti-rot rules stop "temporarily pinned" from becoming permanent — each **fails** the gate: (1) a hold whose `reviewBy` has passed; (2) a hold for a package that is no longer outdated (stale — delete it); (3) a hold with a missing or empty `reason`. Dev-only and runtime dependencies are both reported, tagged `[dev]` / `[runtime]` / `[optional]` so the reader can tell a stale build tool from a stale shipped library. An unreachable registry means the check is **unverified, which is not a pass** — it fails, same as the hosted-CI check. It is classified slow (`--fast` skips it); `prepublishOnly` passes no flags, so a publish always runs it.

---

## Adding a new scan rule

See the **`scanner/src/sast/CLAUDE.md`** local guide. (Moved out of root per the Claude-Code-at-scale guidance: reusable expertise belongs next to the code it applies to, not in the every-session root file.)

The skill `skills/add-scan-rule/SKILL.md` packages the same workflow for on-demand invocation outside the repo (e.g. from a downstream consumer's session).

---

## Claude Code integration

- **Plugin manifest:** `.claude-plugin/plugin.json` — registers the MCP server, hooks, agents, and slash commands.
- **Settings:** `.claude/settings.json` (committed) defines the team's read-deny list — generated bundles, cached benches, scan-state JSON. Override locally via `.claude/settings.local.json` (gitignored).
- **Commands:** markdown files in `commands/` — one per slash command. Index via `/secure --help` (`commands/secure.md`).
- **Agents:** markdown system prompts in `agents/`. Edit-capable agents (`security-fixer`, `refactor-cleaner`) inherit the path-confinement contract in `agents/_CONFINEMENT.md` — same reserved-write list as the MCP server.
- **Hooks:** `hooks/hooks.json` wires SessionStart / UserPromptSubmit / PreToolUse / PostToolUse / Stop. The UserPromptSubmit hook (`hooks/legacy-alias-redirect.js`) maps a removed v0.86.0 alias (`/status`, `/show-findings`, …) to its new dispatcher mode. The Stop hook (`hooks/session-stop-drift-check.js`) flags new files in `scanner/src/{sast,posture,dataflow}/` not yet mentioned in the relevant subdir CLAUDE.md.
- **State:** `.agentic-security/last-scan.json` is the canonical scan output consumed by every downstream command.
- **MCP server:** see `scanner/src/mcp/CLAUDE.md` for tool inventory and hardening posture.

---

## Premortem-derived guardrails

Source comments tagged `(premortem #N)` cross-reference the adversarial-review thread that motivated the change. To find the full set: `git log --grep='premortem'` for commit context, or `grep -rn "premortem #" scanner/src/` for in-code anchors. Living guardrails (the ones future contributors will get wrong without reading) are codified in **Key conventions** above, not here — this section is intentionally short so it doesn't rot.
