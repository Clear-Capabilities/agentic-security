# agentic-security

Full ASPM + LLMSecOps Claude Code plugin. Delivers SAST, SCA (OSV + CISA KEV + function-level reachability), secrets, IaC, prompt-injection, MCP/agent-tool audit, auth/authZ deep analysis, attack chains, PoC generation, SBOM/PBOM/AI-BOM, SARIF ingest, compliance attestation (NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10), and more — local-first, no cloud lock-in.

**Version:** 0.34.10  
**License:** PolyForm Internal Use 1.0.0  
**Author:** Ross Young <ross@clearcapabilities.com> / Clear Capabilities Inc.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `scanner/` | Node.js scan engine (ESM, Node ≥ 20) |
| `scanner/src/engine.js` | Main SAST/SCA/secrets orchestrator |
| `scanner/src/runScan.js` | Top-level scan runner (entry point for CLI) |
| `scanner/src/index.js` | Public API exports |
| `scanner/src/sast/` | SAST modules: authz, cpp, csharp, go-extended, host-header, java-deserialization, jndi, jwt-exp, llm, llm-owasp, logic, mcp-audit, model-load, pipeline, prompt-template, rust, solidity, xxe, zip-slip |
| `scanner/src/sca/` | SCA modules: container, dep-confusion, sarif-ingest |
| `scanner/src/secrets/` | Secrets scanning |
| `scanner/src/posture/` | Posture modules: aibom, api-inventory, drift, license-policy, material-change, mttr, profile, rule-overrides, rule-packs, sbom, scorecard, streak, suppressions, triage |
| `scanner/src/report/` | HTML/JSON/Markdown/SARIF/JUnit report generation |
| `scanner/src/integrations/` | Third-party integrations (CI, PR comment, etc.) |
| `scanner/test/` | Node test runner suite (smoke + unit) |
| `scanner/test/fixtures/` | Per-rule fixture trees used by tests |
| `scanner/dist/` | Compiled single-file bundle (`agentic-security.mjs`) |
| `commands/` | Slash-command markdown files exposed to Claude Code |
| `agents/` | Sub-agent system-prompt definitions |
| `hooks/` | Claude Code hook scripts (`post-edit-scan.js`, `session-welcome.js`, `hooks.json`) |
| `scripts/` | Compliance helper scripts (NIST, OWASP ASVS, OWASP LLM Top 10) and PR comment helper |
| `vscode/` | VS Code extension source (`vscode/src/extension.ts`) |
| `docs/` | Developer documentation and compliance reference materials |
| `.claude-plugin/` | Plugin manifest (`plugin.json`, `marketplace.json`) |
| `.agentic-security/` | Runtime state: last scan, streak, rules override, hook throttle |
| `data/` | Static data bundled with the scanner |

---

## Build & test

```bash
# Working directory: scanner/
npm install
npm run build          # bundles dist/agentic-security.mjs via @vercel/ncc
npm test               # full Node test runner suite (all test/*.test.js files)
npm run smoke          # quick sanity scan against test/fixtures/vulnerable-js
npm run bench          # performance benchmark against baseline
npm run bench:update   # update benchmark baseline
npm run bench:realworld   # real-world benchmark suite
npm run bench:llm-goats   # LLM-specific adversarial benchmark
```

The build step must be run after any change to `scanner/src/` or `scanner/bin/` before the CLI (`dist/agentic-security.mjs`) reflects those changes.

---

## SAST modules (scanner/src/sast/)

Each file exports one or more `scan*()` functions:

| Module | Coverage |
|--------|----------|
| `authz.js` | Authorization / access-control flaws |
| `cpp.js` | C/C++ memory safety, buffer overflows |
| `csharp.js` | C# deserialization, injection |
| `go-extended.js` | Go-specific security patterns |
| `host-header.js` | Host header injection |
| `java-deserialization.js` | Java unsafe deserialization |
| `jndi.js` | JNDI injection (Log4Shell family) |
| `jwt-exp.js` | JWT without expiry / weak signing |
| `llm.js` | Prompt injection, LLM safety |
| `llm-owasp.js` | OWASP LLM Top 10 (2025) coverage |
| `db-rls.js` | Supabase RLS misconfig, service-role key exposure, admin API misuse |
| `auth-provider.js` | Auth provider misconfig (Clerk, NextAuth, Auth0, Lucia, generic OAuth) |
| `env-hygiene.js` | NEXT_PUBLIC_ secret leaks, .env.example real values, hardcoded fallbacks |
| `rate-limit.js` | Missing rate limiting on auth, AI, payment, and contact endpoints |
| `webhook.js` | Webhook handlers missing provider signature verification (Stripe, GitHub, Clerk, Svix) |
| `client-side.js` | React/JSX: dangerouslySetInnerHTML XSS, localStorage tokens, open redirect, postMessage |
| `prompt-firewall.js` | LLM defense gaps: user input in system prompt, missing max_tokens, output→SQL/exec |
| `logic.js` | Business-logic flaws, IDOR, state-machine bypasses |
| `mcp-audit.js` | MCP / agent-tool security audit |
| `model-load.js` | Unsafe ML model loading (`torch.load`, `pickle`, `trust_remote_code`) |
| `pipeline.js` | CI/CD pipeline integrity |
| `prompt-template.js` | Prompt template injection |
| `rust.js` | Rust `unsafe` blocks, memory patterns |
| `solidity.js` | Solidity / smart-contract vulnerabilities |
| `xxe.js` | XML External Entity (XXE) injection |
| `zip-slip.js` | Zip-slip / path traversal in archives |

---

## Posture modules (scanner/src/posture/)

| Module | Purpose |
|--------|---------|
| `aibom.js` | AI-BOM generation (CycloneDX 1.7 ML-BOM) |
| `api-inventory.js` | API surface inventory |
| `drift.js` | Security-posture drift detection |
| `license-policy.js` | License compliance enforcement |
| `material-change.js` | Security-materiality scoring for diffs |
| `mttr.js` | MTTR / SLA tracking |
| `profile.js` | Project risk profile |
| `rule-overrides.js` | Per-project rule enable/disable/tune |
| `rule-packs.js` | Named rule-pack loading |
| `sbom.js` | SBOM generation (CycloneDX + SPDX) |
| `scorecard.js` | OpenSSF Scorecard-style scoring |
| `deploy-platform.js` | Deployment-platform security audit (Vercel, Railway, Fly.io, Netlify, Cloudflare) |
| `stack-playbook.js` | Stack-specific security playbook generator (Next.js, Supabase, Stripe, Clerk, etc.) |
| `security-trend.js` | Rolling scan-history snapshots and regression delta computation |
| `streak.js` | Clean-scan streak tracking |
| `suppressions.js` | Suppression-pragma management |
| `triage.js` | Finding deduplication and ranking |

---

## Test suite (scanner/test/)

Tests use the Node built-in test runner. Key test files:

`smoke`, `llm`, `llm-owasp`, `logic`, `fn-reach`, `material-change`, `drift`, `sbom`, `api-inventory`, `sarif-ingest`, `pipeline`, `license-policy`, `mttr`, `container`, `dep-confusion`, `scorecard`, `mcp-audit`, `authz`, `kev`, `model-load`, `prompt-template`, `aibom`, `packs`, `junit`, `ci`

New modules (`db-rls`, `rate-limit`, `auth-provider`, `env-hygiene`, `deploy-platform`, `stack-playbook`) are integration-tested via `npm run smoke` and inline module tests. Dedicated test files should be added under `test/` to match the pattern above.

---

## Key conventions

- **ESM throughout** — all `scanner/src/` files use `import`/`export`; no CommonJS.
- **No runtime cloud calls** — OSV/KEV data is fetched lazily and disk-cached under `~/.claude/agentic-security/osv-cache/`. Avoid adding network dependencies that break offline use.
- **File-context inference** — `inferFileContext()` in `engine.js` gates rules by runtime kind (server / CLI / hook / extension / serverless). Respect this when adding rules.
- **Findings schema** — every finding must include `{ id, title, severity, file, line, description, remediation }`. Severity values: `critical`, `high`, `medium`, `low`, `info`.
- **Suppression pragmas** — `// agentic-security-ignore: <rule-id>` on a line suppresses that rule for that line.
- **Rules override** — `.agentic-security/rules.yml` in any project can enable/disable/tune rules without touching scanner source.
- **Test fixtures** — add a minimal fixture directory under `scanner/test/fixtures/<rule-name>/` when adding a new rule; the smoke test should detect the vuln in `vulnerable/` and pass on `clean/`.

---

## Adding a new scan rule

1. Pick the right module (`sast/`, `sca/`, `secrets/`, `posture/`).
2. Export a `scan*()` function that returns `Finding[]`.
3. Import and call it in `engine.js`.
4. Add a fixture pair (`vulnerable/` + `clean/`) under `scanner/test/fixtures/`.
5. Cover it in the relevant `test/*.test.js` file.
6. Run `npm run build` and verify with `npm run smoke`.

---

## Claude Code integration

- **Plugin manifest:** `.claude-plugin/plugin.json` — controls name, version, skill/agent/command registration.
- **Commands:** markdown files in `commands/` — one per slash command.
- **Agents:** markdown system prompts in `agents/` — loaded as sub-agents by the harness.
- **Hooks:** `hooks/hooks.json` declares which Claude Code events trigger which scripts (`post-edit-scan.js`, `session-welcome.js`).
- **State:** `.agentic-security/last-scan.json` holds the most recent scan output used by downstream commands (fix, report, chain, drift, etc.).
- **VS Code extension:** `vscode/src/extension.ts` — IDE integration source.
- **PR comments:** `scripts/pr-comment.js` — posts scan results as GitHub PR review comments.
