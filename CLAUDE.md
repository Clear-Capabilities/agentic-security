# agentic-security

Full ASPM + LLMSecOps Claude Code plugin. Delivers SAST, SCA (OSV + CISA KEV + function-level reachability), secrets, IaC, prompt-injection, MCP/agent-tool audit, auth/authZ deep analysis, attack chains, PoC generation, SBOM/PBOM/AI-BOM, SARIF ingest, and compliance attestation (NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10).

**Version:** 0.45.0  
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
| `scanner/src/sast/` | SAST modules: authz, cpp, cpp-bench-extras, csharp, go-extended, host-header, java-bench-extras, java-collection-passthrough, java-deserialization, jndi, juliet-shape, jwt-exp, llm, llm-owasp, logic, mcp-audit, model-load, pipeline, prompt-template, rust, solidity, xxe, zip-slip |
| `scanner/src/sca/` | SCA modules: container, dep-confusion, sarif-ingest |
| `scanner/src/secrets/` | Secrets scanning |
| `scanner/src/posture/` | Posture modules: aibom, api-inventory, blast-radius, custom-rules, deterministic, drift, epss, fix-history, license-policy, material-change, mttr, profile, router, rule-overrides, rule-packs, sbom, scorecard, streak, suppressions, triage |
| `scanner/src/report/` | HTML/JSON/Markdown/SARIF/JUnit report generation |
| `scanner/src/integrations/` | Third-party integrations (CI, PR comment, etc.) — Slack/Discord/Teams webhooks, GitHub/GitLab PR comments, Jira/Linear/GitHub/ServiceNow ticketing, PagerDuty events |
| `scanner/src/llm-validator/` | Layer-3 LLM validator (Sentinel-parity FR-L3). Calls an LLM endpoint per candidate finding for accept/reject/escalate verdicts; cache-keyed by `(file_hash, path_signature, prompt_version, model_id)` for byte-deterministic re-runs. No-op when `AGENTIC_SECURITY_LLM_ENDPOINT` is unset — every finding is marked `unvalidated:true`. Opt-in via `AGENTIC_SECURITY_LLM_VALIDATE=1`. |
| `scanner/src/ir/` | Layer-1 IR (Sentinel-parity FR-L1). Babel-based JS/TS frontend producing per-function CFG (entry/exit/assign/call/return/if/loop nodes) + cross-file call graph keyed by stable function `qid`. Opt-in via `AGENTIC_SECURITY_DEEP=1`. |
| `scanner/src/dataflow/` | Layer-2 interprocedural taint engine (Sentinel-parity FR-L2). Walks the IR with field-sensitive forward taint, recognizes sources/sinks/sanitizers from a 140+ entry structured catalog (`catalog.js`) spanning Express/Flask/FastAPI/Django/Spring/Rails/PHP/Go-net-http/Gin/Echo, prunes infeasible branches via constant-folding (`path-feasibility.js`), caches per-function summaries by entry-taint-state hash (`summaries.js`, k=1 monovariant). Findings tagged `parser: 'IR-TAINT'`. |
| `scanner/src/lsp/` | Minimal LSP server that wraps `runScan` and emits `textDocument/publishDiagnostics` to the editor. Used by the bundled JetBrains plugin (`jetbrains-plugin/`) and Neovim plugin (`nvim-plugin/`). Bin entry: `bin/agentic-security-lsp.js`. |
| `jetbrains-plugin/` | LSP4IJ-backed JetBrains plugin (IntelliJ / PyCharm / GoLand / WebStorm / RubyMine / PhpStorm) that surfaces findings inline. ~100 LoC + `plugin.xml`. Build with `./gradlew buildPlugin`. |
| `nvim-plugin/` | Native-LSP Neovim plugin (Lua). Attaches the bundled LSP server on filetype-matched buffers. Install via lazy.nvim / vim-plug. |
| `scanner/src/mcp/` | MCP server: stdio JSON-RPC handler + six agent-callable tools (`scan_diff`, `query_taint`, `explain_finding`, `apply_fix`, `verify_fix`, `synthesize_fix`) |
| `bench/cve-replay/` | Phase-0 measurement scaffolding for the F1 ≥ 0.85 target. `runner.mjs` scans each `cves/<id>/{pre,post}/` fixture and computes TP/FP/FN per CVE; aggregate F1 in `bench/cve-replay/results/`. Run via `npm run bench:cve-replay`. |
| `scripts/ci-templates/` | Drop-in CI configs for GitLab CI / CircleCI / Buildkite / Jenkins. Consumed by `/ci-gate-multi`. |
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
| `juliet-shape.js` | Benchmark-shape detector for NIST SARD Juliet — reads the test-suite's own `/* FLAW: */` and `/* POTENTIAL FLAW: */` markers and the `juliet-cwe<N>/` / `testcases/CWE<N>_*/` folder names. **This is label-leakage and is disabled in blind benchmarking** (set `AGENTIC_SECURITY_BLIND_BENCH=1`). Kept only because it makes Juliet integration smoke tests human-readable; never use its emissions as a quality signal. |
| `cpp-bench-extras.js` | Juliet C/C++ primary-CWE family suppressor — drops findings on Juliet test files for unmapped CWEs |
| `java-bench-extras.js` | OWASP Benchmark template suppressors (Map double-get safe-key, switch-charAt(1)-condition-B-safe, ListShuffle, ConstantTernary, ThingFlow, etc.) gated to `_BAR_USING_FAMILIES` |
| `java-collection-passthrough.js` | Java taint passthrough through `Vector`/`List`/`Map`/`Stream`/`Optional`/array-literal collection extractions |
| `kotlin.js` | Kotlin-specific patterns — `!!` force-unwrap on user input, `runBlocking` on event loops, unsafe SnakeYAML, `Gson.fromJson(_, Any::class)`, `File.readText` with user-controlled path, `Runtime.exec` with user input |
| `ruby.js` | Ruby idioms — eval/instance_eval, `send`/`public_send` with user input, Marshal.load, YAML.load, ERB on user template, backtick / system / Open3 with user input, mass-assignment without strong_params |
| `php.js` | PHP foot-guns — `$_REQUEST` into eval/system/exec/passthru/assert, `unserialize` on user input, `include`/`require` with user-controlled path, `mysql_query` concat, `extract($_REQUEST)`, md5/sha1 for passwords, `phpinfo()` |
| `mass-assignment.js` | Mass assignment / over-posting — Express, Mongoose, Sequelize, Prisma, Rails, Django, Spring, GORM. Allow-list (`pick`/`permit`/`strong_params`) presence downgrades to low |
| `prototype-pollution.js` | JS/TS prototype pollution — lodash.merge/set, hand-rolled deep merges, direct writes to `__proto__`/`constructor.prototype` |
| `csrf.js` | CSRF on state-changing routes — POST/PUT/PATCH/DELETE without csurf, CSRFProtect, CsrfFilter, SameSite=Strict/Lax, or Bearer-token auth |
| `toctou.js` | Time-of-check / time-of-use — `fs.access` → `fs.readFile`, `os.path.exists` → `open`, auth-check + `await` + sensitive side-effect |
| `nosql-injection.js` | Mongo `$where` concat, Mongoose `find(req.body)` operator injection, DynamoDB expression concat |
| `ldap-injection.js` | LDAP filter string built via concatenation — Node ldapjs, Java JNDI, Python ldap3 |
| `xpath-injection.js` | XPath query built via concatenation — javax.xml.xpath, lxml, Node xpath |
| `ssrf-cloud-metadata.js` | Cloud-metadata-aware SSRF — flags user-controlled URLs without an explicit deny-list of 169.254.169.254, metadata.google.internal, Azure IMDS, fd00:ec2::254 |
| `mutation-xss.js` | mXSS — DOMParser → `.body.innerHTML` round-trip, XMLSerializer into innerHTML, double-innerHTML re-assignment |
| `deserialization-gadgets.js` | Combines unsafe-deserialization sinks with classpath gadget-library presence (commons-collections, spring-aop, snakeyaml, etc.) — bumps to critical when both present |

---

## Posture modules (scanner/src/posture/)

| Module | Purpose |
|--------|---------|
| `aibom.js` | AI-BOM generation (CycloneDX 1.7 ML-BOM) |
| `llm-redteam.js` + `llm-redteam-prompts.js` | Red-team prompt corpus (30+ prompts across 7 promptfoo-aligned harm categories) + active-test runner (sends prompts to an LLM endpoint and judges responses) + 7 attack-strategy mutations (DAN, base64, ROT13, role-play, authority-claim, hypothetical, multilingual, chained-context) + static SAST scan for LLM-call defense gaps |
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
| `epss.js` | EPSS exploit-prediction enrichment (FIRST.org, disk-cached). Bumps severity on percentile ≥ 95% |
| `blast-radius.js` | Plain-English cost / blast-radius narrative per finding (uses project signals: Stripe, auth, schema, .env) |
| `custom-rules.js` | YAML pattern-rule DSL (`.agentic-security/rules/*.yml`) + `rule test` harness |
| `fix-history.js` | Fix preview / apply / undo with backups under `.agentic-security/fix-history/` |
| `deterministic.js` | `--deterministic` mode + rule-pack lockfile (`rules.lock.json`) |
| `router.js` | Smart `secure` decision tree — routes vibecoders to the right next action |
| `confidence.js` | Calibrated 0.0–1.0 confidence on every finding (FR-PREC) — combines severity prior, triage score, parser/evidence/sanitizer signals; tier label in `confidenceTier` |
| `stable-id.js` | Refactor-stable finding IDs — hash of `(rule_id, normalized_sink_signature, path_shape, basename-pair)` so renames/reformats don't rotate IDs |
| `clustering.js` | Root-cause clustering within a file — multiple flows converging on the same sink collapse into one finding with `clusterSize` and `exampleFlows` |
| `reachability-filter.js` | Demotes findings marked `reachable:false` to `unreachable:true` + lower severity, but only when the project has route handlers (so isolated fixture scans are unaffected) |
| `exploitability.js` | Composite 0.0–1.0 exploitability score — severity + reachability + auth gating + project mitigations (CSP/Helmet/WAF/auth middleware) + KEV/EPSS |
| `learning.js` | Active-learning loop — consumes `.agentic-security/triage-feedback.json` (from `/triage`); past FPs by stableId or pattern get suppressed; past TPs get a confidence bump |
| `fix-verify.js` | Closed-loop `/fix` verification — re-scan after patch + run project linter (eslint / ruff / golangci-lint / checkstyle). Returns `ok:false` and a structured reason when the patch doesn't actually remove the original finding or introduces new ≥medium findings |
| `cross-lang-openapi.js` | Cross-language taint via OpenAPI — when `openapi.{json,yaml}` is present, maps client `fetch`/`axios`/`requests` calls to server-side route handlers and emits `cross_language:true` chains when the server-side handler carries a high+ finding |
| `cross-lang-grpc.js` | Cross-language taint via gRPC — parses `*.proto` files, matches client stub call sites to server impls (Go/Java/Python/Node), emits chains when the server impl carries a high+ finding |
| `cross-lang-graphql.js` | Cross-language taint via GraphQL — parses `*.graphql` SDL, matches `gql` client queries to resolver impls (Apollo/NestJS/Strawberry/Graphene), emits chains when the resolver carries a high+ finding |
| `cross-lang-orm.js` | SQL/ORM round-trip taint — detects ORM writes (Mongoose/Sequelize/Prisma/SQLAlchemy/Django/ActiveRecord/GORM) with tainted values into table.column, then reads of the same model — emits a round-trip chain |
| `iac-reachability.js` | IaC → application code reachability — parses Terraform resource blocks, identifies publicly-exposed S3/RDS/SG/ALB/Lambda-URL/ECS resources, then correlates with application code that references those resource names (env-var or string literal). Bumps severity on findings near IaC-exposed references |
| `fix-plan.js` | Fix-plan emission when a proposed patch exceeds the ≤3 files / ≤100 LoC bounds. Renders a numbered markdown plan to `.agentic-security/fix-plans/<stableId>.md` instead of dumping an unverifiable patch (PRD FR-FIX-1/FR-FIX-3). |
| `path-predicates.js` | SentQL `path: { must_traverse, must_not_traverse }` runtime predicate evaluator. Predicate catalog: `is_http_route`, `is_sanitized`, `is_auth_guarded`, `has_unauth_route`, `is_cross_file`, `is_reachable`, `has_multi_step_path` (plus `not_*` inverses). |
| `validator-metrics.js` | Persistent per-CWE precision/recall scorecard at `.agentic-security/validator-metrics.json`. The bench-realworld runner appends to history on every run; per-family floor configuration supports the PRD's ≥0.92 recall target. |

## Integrations (scanner/src/integrations/)

| Module | Purpose |
|--------|---------|
| `index.js` | Slack / Discord digests, Jira / ServiceNow issue builders, SIEM event, PR-comment renderer |
| `tickets.js` | Two-way ticket sync (GitHub Issues via `gh`, Linear via GraphQL, Jira via REST). Idempotent state in `.agentic-security/tickets.json` |

---

## Test suite (scanner/test/)

Tests use the Node built-in test runner. Key test files:

`smoke`, `llm`, `llm-owasp`, `logic`, `fn-reach`, `material-change`, `drift`, `sbom`, `api-inventory`, `sarif-ingest`, `pipeline`, `license-policy`, `mttr`, `container`, `dep-confusion`, `scorecard`, `mcp-audit`, `mcp` (MCP server), `authz`, `kev`, `model-load`, `prompt-template`, `aibom`, `packs`, `junit`, `ci`, `cpp-dataflow` (requires `AGENTIC_SECURITY_CPP_DATAFLOW=1`)

New modules (`db-rls`, `rate-limit`, `auth-provider`, `env-hygiene`, `deploy-platform`, `stack-playbook`) are integration-tested via `npm run smoke` and inline module tests. Dedicated test files should be added under `test/` to match the pattern above.

---

## Key conventions

- **ESM throughout** — all `scanner/src/` files use `import`/`export`; no CommonJS.
- **No runtime cloud calls** — OSV/KEV data is fetched lazily and disk-cached under `~/.claude/agentic-security/osv-cache/`. Avoid adding network dependencies that break offline use.
- **File-context inference** — `inferFileContext()` in `engine.js` gates rules by runtime kind (server / CLI / hook / extension / serverless). Respect this when adding rules.
- **Findings schema** — every finding must include `{ id, title, severity, file, line, description, remediation }`. Severity values: `critical`, `high`, `medium`, `low`, `info`. Phase-1 (Sentinel-parity) extends every finding with: `stableId` (16-hex, refactor-stable), `confidence` ∈ [0,1] + `confidenceTier`, `exploitability` ∈ [0,1] + `exploitabilityTier` + `exploitabilityFactors[]`, optionally `clusterSize` and `exampleFlows[]` for root-cause-clustered findings, and `unreachable:true` on findings demoted by the reachability filter. SARIF emit carries these as properties.
- **Suppression pragmas** — `// agentic-security-ignore: <rule-id>` on a line suppresses that rule for that line.
- **Rules override** — `.agentic-security/rules.yml` in any project can enable/disable/tune rules without touching scanner source.
- **Shadow mode** — custom rules with `shadow: true` emit to `.agentic-security/shadow-findings.json` and are excluded from CI gates. Use for experimental rules not yet ready for blocking.
- **Bench-shape isolation** — all answer-key reading (Juliet folder names, OWASP template markers, `@WebServlet` prefix) lives in `sast/bench-shape/` and is OFF by default. Set `AGENTIC_SECURITY_BENCH_SHAPE=1` to enable (done automatically by `bench-realworld.js`). `AGENTIC_SECURITY_BLIND_BENCH=1` overrides to force everything off.
- **last-scan.json integrity** — each write is accompanied by a `.sig` file (HMAC-SHA256). A tamper warning is printed on read if the sig doesn't match.
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
- **Commands:** markdown files in `commands/` — one per slash command. Phase-1 (Sentinel-parity) additions: `/triage` (interactive verdict capture → `.agentic-security/triage-feedback.json`, consumed by the active-learning loop on the next scan), `/why-not <CWE>` (recall spot-check — shows what the engine considered for the CWE and why nothing fired), `/query` (SentQL prompt — natural-language description translated into the existing YAML rule DSL). Phase-2 additions: `/install-hooks` (pre-commit and pre-push git-hook installer, blocks on new critical findings; `--uninstall` to remove), `/ci-gate-multi` (auto-detects GitLab CI / CircleCI / Buildkite / Jenkins and emits the matching template from `scripts/ci-templates/`).
- **Agents:** markdown system prompts in `agents/` — loaded as sub-agents by the harness.
- **Hooks:** `hooks/hooks.json` declares which Claude Code events trigger which scripts (`post-edit-scan.js`, `session-welcome.js`, `pre-edit-bodyguard.js`, `pre-bash-guard.js`, `conversation-context.js`). The conversation-context hook injects open findings + recent `/fix` history + pending fix-plans for the file being edited so Claude doesn't re-introduce a just-fixed vuln.
- **State:** `.agentic-security/last-scan.json` holds the most recent scan output used by downstream commands (fix, report, chain, drift, etc.).
- **VS Code extension:** `vscode/src/extension.ts` — IDE integration source.
- **PR comments:** `scripts/pr-comment.js` — posts scan results as GitHub PR review comments.
- **MCP server:** registered in `plugin.json#mcpServers`. Bin entry `scanner/bin/agentic-security-mcp.js`, also reachable via `agentic-security mcp`. Exposes six tools any MCP-speaking agent (Claude Code, Cursor CLI, Codex CLI, Cline, Aider) can call: `scan_diff(files)`, `query_taint(source, sink)`, `explain_finding(finding_id)`, `apply_fix(finding_id, confirm, dry_run?)`, `verify_fix(stable_id, files)` (re-scan + lint, no writes), `synthesize_fix(finding_id)` (returns replacement + bounds, no writes). Transport: JSON-RPC 2.0 over NDJSON on stdin/stdout.
  - **Session root** is fixed at boot (`--root` arg, `AGENTIC_SECURITY_MCP_ROOT` env, or cwd). All tool paths are confined under it via lstat + realpath (symlinks refused).
  - **Kill switch:** `AGENTIC_SECURITY_MCP_DISABLED=1` exits the bin and refuses every `tools/call` (OWASP MCP09).
  - **Integrity:** `apply_fix` refuses unless `last-scan.json` HMAC verifies; tool outputs include `_meta.untrusted_excerpts:true` so the agent treats scanner output as data, not instructions (OWASP MCP03/MCP06).
  - **Secret hygiene:** all tool outputs and audit args are redacted of known credential shapes (AWS, GitHub, Slack, Anthropic, OpenAI, Stripe, JWT, PEM private keys, hardcoded password literals) — OWASP MCP01/MCP10.
  - **Audit log:** `.agentic-security/mcp-audit.log` (NDJSON, hash-chained — verify with `verifyAuditLog`) records every `tools/call`. OWASP MCP08.
  - **Fleet visibility:** `initialize` response includes `serverInfo.codeFingerprint` (SHA-256 of MCP source files) so an operator can detect unauthorized builds. OWASP MCP04/MCP09.
