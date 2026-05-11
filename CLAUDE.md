# agentic-security

Full ASPM + LLMSecOps Claude Code plugin. Delivers SAST, SCA (OSV + CISA KEV + function-level reachability), secrets, IaC, prompt-injection, MCP/agent-tool audit, auth/authZ deep analysis, attack chains, PoC generation, SBOM/PBOM/AI-BOM, SARIF ingest, compliance attestation (NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2), and more — local-first, no cloud lock-in.

**License:** PolyForm Internal Use 1.0.0  
**Author:** Ross Young <ross@clearcapabilities.com> / Clear Capabilities Inc.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `scanner/` | Node.js scan engine (ESM, Node ≥ 20) |
| `scanner/src/engine.js` | Main SAST/SCA/secrets orchestrator |
| `scanner/src/sast/` | SAST modules: authz, llm, logic, mcp-audit, model-load, pipeline, prompt-template |
| `scanner/src/sca/` | SCA modules: container, dep-confusion, sarif-ingest |
| `scanner/src/secrets/` | Secrets scanning |
| `scanner/src/posture/` | Posture modules: sbom, license-policy, scorecard |
| `scanner/src/report/` | HTML/JSON/Markdown/SARIF report generation |
| `scanner/test/` | Node test runner suite (smoke + unit) |
| `scanner/test/fixtures/` | Per-rule fixture trees used by tests |
| `scanner/dist/` | Compiled single-file bundle (`agentic-security.mjs`) |
| `commands/` | Slash-command markdown files exposed to Claude Code |
| `skills/` | Skill entry points (fix-vulnerability, sast-scan, sca-scan, secret-scan, nist-ai-600-1) |
| `agents/` | Sub-agent system-prompt definitions |
| `hooks/` | Claude Code hook scripts (post-edit scan, session welcome) |
| `scripts/` | Compliance helper scripts (NIST, SOC 2, PCI-DSS, OWASP ASVS) |
| `.claude-plugin/` | Plugin manifest (`plugin.json`, `marketplace.json`) |
| `.agentic-security/` | Runtime state: last scan, streak, rules override, hook throttle |
| `data/` | Static data bundled with the scanner |

---

## Build & test

```bash
# Working directory: scanner/
npm install
npm run build      # bundles dist/agentic-security.mjs via @vercel/ncc
npm test           # full Node test suite (all test/*.test.js files)
npm run smoke      # quick sanity scan against test/fixtures/vulnerable-js
npm run bench      # performance benchmark
```

The build step must be run after any change to `scanner/src/` or `scanner/bin/` before the CLI (`dist/agentic-security.mjs`) reflects those changes.

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
- **Hooks:** `hooks/hooks.json` declares which Claude Code events trigger which scripts.
- **State:** `.agentic-security/last-scan.json` holds the most recent scan output used by downstream commands (fix, report, chain, drift, etc.).
