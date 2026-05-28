# agentic-security

Full ASPM + LLMSecOps Claude Code plugin. Delivers SAST, SCA (OSV + CISA KEV + function-level reachability), secrets, IaC, prompt-injection, MCP/agent-tool audit, auth/authZ deep analysis, attack chains, PoC generation, SBOM/PBOM/AI-BOM, SARIF ingest, and compliance attestation (NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10, EU AI Act).

**Version:** 0.79.0  
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
| `scanner/src/mcp/` | MCP server. Six tools; OWASP MCP Top 10 hardened. | `scanner/src/mcp/CLAUDE.md` |
| `scanner/src/ir/` | Layer-1 IR: Babel-based JS/TS; Python via stdlib `ast` subprocess (default, when python3 available) with regex fallback; `java-parser`-based Java. | `scanner/src/ir/CLAUDE.md` |
| `scanner/src/lsp/` | LSP server wrapping `runScan`. Ships with the JetBrains + Neovim plugins. |  |
| `scanner/src/llm-validator/` | Layer-3 LLM validator (opt-in via `AGENTIC_SECURITY_LLM_VALIDATE=1`). |  |
| `scanner/test/` | Node test runner suite. Scoped via `npm run test:{smoke,sast,posture,dataflow,mcp,report,lifecycle}` — see `scanner/CLAUDE.md`. |  |
| `bench/cve-replay/` | Real-CVE replay corpus + runner. Six entries today; target 500 (`bench/cve-replay/CONTRIBUTING.md`). |  |
| `bench/owasp-benchmark-v1.2/`, `bench/sard-juliet-java/`, `bench/polyglot/` | External benches (gitignored, regenerated). |  |
| `commands/` | Slash-command markdown files (~77). |  |
| `agents/` | Sub-agent system prompts. Edit-capable agents follow `agents/_CONFINEMENT.md`. |  |
| `hooks/` | Claude Code hook scripts + `hooks.json`. |  |
| `scripts/` | Compliance + helper scripts + CI templates (`scripts/ci-templates/`). |  |
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

---

## Key conventions (the things you'll get wrong without reading them)

- **ESM throughout.** All `scanner/src/` files use `import`/`export`. No CommonJS in the scanner tree.
- **No runtime cloud calls.** OSV/KEV/EPSS data is fetched lazily and disk-cached under `~/.claude/agentic-security/osv-cache/`. New network dependencies must be opt-in and degrade gracefully when offline.
- **Findings schema.** Every finding must include `{ id, severity, file, line, vuln, cwe, description, remediation, parser, family }`. Severity values: `critical`, `high`, `medium`, `low`, `info`. Phase-1 extends with `stableId`, `confidence` + `confidenceTier`, `exploitability` + `exploitabilityTier` + `exploitabilityFactors[]`, optionally `clusterSize` / `exampleFlows[]`, and `unreachable:true` for reachability-demoted. `parser` + `family` are required — `posture/finding-defaults.js` backfills, but detector-set values win.
- **Suppression pragma.** `// agentic-security-ignore: <rule-id>` on the offending line.
- **Rules override is gated.** `.agentic-security/rules.yml` `disable:` entries take effect only when a sibling `.sig` verifies under the per-install HMAC key, or `AGENTIC_SECURITY_RULES_UNSIGNED=1` is set. `severityOverrides`, `custom:`, and `ignorePaths` are not gated (they don't reduce coverage).
- **last-scan.json integrity.** Each write is accompanied by a `.sig` (HMAC-SHA256). The key is per-install (32 random bytes at `$XDG_CONFIG_HOME/agentic-security/scan-key`, mode 0600) — NOT the hostname. Override via `$AGENTIC_SECURITY_HMAC_KEY` (hex).
- **Calibration is held-out-only.** The seed corpus is for *fitting* the calibration table; never compute Brier/ECE against the same labels. Use `posture/holdout-eval.js` with a separate JSONL.
- **Bench-shape isolation.** Answer-key reading (Juliet folder names, OWASP template markers) lives under `sast/bench-shape/` and is OFF by default. `AGENTIC_SECURITY_BENCH_SHAPE=1` enables; `AGENTIC_SECURITY_BLIND_BENCH=1` overrides to force off.
- **Shadow mode.** Custom rules with `shadow: true` write to `.agentic-security/shadow-findings.json` and are excluded from CI gates — for experimental rules not yet ready to block.
- **Test fixtures.** New rules need a minimal `vulnerable/` + `clean/` pair under `scanner/test/fixtures/<rule-name>/`. Smoke must detect in `vulnerable/`, must pass on `clean/`.

---

## Adding a new scan rule

See the **`scanner/src/sast/CLAUDE.md`** local guide. (Moved out of root per the Claude-Code-at-scale guidance: reusable expertise belongs next to the code it applies to, not in the every-session root file.)

The skill `skills/add-scan-rule.md` packages the same workflow for on-demand invocation outside the repo (e.g. from a downstream consumer's session).

---

## Claude Code integration

- **Plugin manifest:** `.claude-plugin/plugin.json` — registers the MCP server, hooks, agents, and slash commands.
- **Settings:** `.claude/settings.json` (committed) defines the team's read-deny list — generated bundles, cached benches, scan-state JSON. Override locally via `.claude/settings.local.json` (gitignored).
- **Commands:** markdown files in `commands/` — one per slash command. Index in `commands/help.md`.
- **Agents:** markdown system prompts in `agents/`. Edit-capable agents (`security-fixer`, `refactor-cleaner`) inherit the path-confinement contract in `agents/_CONFINEMENT.md` — same reserved-write list as the MCP server.
- **Hooks:** `hooks/hooks.json` wires SessionStart / PreToolUse / PostToolUse / Stop. The Stop hook (`hooks/session-stop-drift-check.js`) flags new files in `scanner/src/{sast,posture,dataflow}/` not yet mentioned in the relevant subdir CLAUDE.md.
- **State:** `.agentic-security/last-scan.json` is the canonical scan output consumed by every downstream command.
- **MCP server:** see `scanner/src/mcp/CLAUDE.md` for tool inventory and hardening posture.

---

## Premortem-derived guardrails

Source comments tagged `(premortem #N)` cross-reference the adversarial-review thread that motivated the change. To find the full set: `git log --grep='premortem'` for commit context, or `grep -rn "premortem #" scanner/src/` for in-code anchors. Living guardrails (the ones future contributors will get wrong without reading) are codified in **Key conventions** above, not here — this section is intentionally short so it doesn't rot.
