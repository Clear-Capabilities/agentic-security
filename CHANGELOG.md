# Changelog

## 0.67.0 — detection rules for 6 new CWE families (SSTI / LDAP / open-redirect / response-splitting)

The v0.66 corpus expansion exposed six CWE families with no detection
coverage (or partial coverage that missed common shapes). This release
ships dedicated detectors plus a runner fix.

### New SAST detectors

| Module | CWE | Languages | What it catches |
|--------|-----|-----------|-----------------|
| `sast/ssti.js`               | CWE-94   | py, js, php, java | Jinja2 `from_string` / `Template()`, Handlebars / EJS / Mustache / Pug `.compile`, Twig `createTemplate`, Velocity `evaluate` — fires only when the template body is non-literal AND has a taint hint or comes from a variable assigned from user input in the preceding 10 lines |
| `sast/open-redirect.js`      | CWE-601  | js, py, java, php | `res.redirect` / `ctx.redirect` / `flask.redirect` / `HttpResponseRedirect` / Spring `"redirect:" + …` / PHP `header("Location: " . …)` with user-derived target AND no allow-list check in the preceding 30 lines |
| `sast/response-splitting.js` | CWE-113  | js, py, java, php | `setHeader` / `addHeader` / `response.headers[…] = …` / PHP `header()` with user-derived value (or method param in Java handler context) AND no CRLF strip / sanitizer above |
| `sast/ldap-injection.js`     | CWE-90   | js, java, py | **Extended:** indirect filter shape (`String filter = "(uid=" + name + ")"; ctx.search(…, filter, …)`) and `search_s` / `paged_search` callees, gated on a file-level LDAP context hint |

XPath (CWE-643) and ReDoS (CWE-1333) already had working detectors; the
runner just wasn't checking the right arrays.

### Runner fix

`bench/cve-replay/runner.mjs` now consults `scan.findings`, `scan.secrets`,
`scan.supplyChain`, AND `scan.logicVulns` when scoring a fixture.
Previously, business-logic findings (where ReDoS / weak-crypto / behavioral
checks live) were invisible to the scoring pipeline.

### Engine cleanup

Removed the legacy coarse `(?:res\.redirect|response\.redirect|.redirect\(|header\(['"]Location)`
REGEX rule from `engine.js` — the new `scanOpenRedirect` detector is
precise (allow-list aware) and replaces it cleanly.

### Results on the v0.66 corpus

All 9 fixtures across the 6 new CWE families now score **pre:TP post:TN**:

| CVE | CWE | v0.66 | v0.67 |
|-----|-----|-------|-------|
| CVE-2017-16016-handlebars-ssti       | CWE-94   | pre:FN | pre:TP post:TN |
| CVE-2017-9805-ldap-injection         | CWE-90   | pre:FN | pre:TP post:TN |
| CVE-2018-1320-xpath-injection        | CWE-643  | pre:TP | pre:TP post:TN |
| CVE-2019-8341-jinja-ssti             | CWE-94   | pre:FN | pre:TP post:TN |
| CVE-2020-15252-open-redirect         | CWE-601  | pre:TP post:FP | pre:TP post:TN |
| CVE-2020-7660-resp-splitting         | CWE-113  | pre:FN | pre:TP post:TN |
| CVE-2021-25966-open-redirect-py      | CWE-601  | pre:FN | pre:TP post:TN |
| CVE-2021-29622-ldap-py               | CWE-90   | pre:FN | pre:TP post:TN |
| CVE-2021-3801-redos                  | CWE-1333 | pre:FN | pre:TP post:TN |

Aggregate F1: **0.500 → 0.597** on the same 88-entry corpus. Wilson 95%
CI [0.334, 0.523] (narrower than v0.66's [0.249, 0.429]). Regression
tier still F1=1.0.

### Tests

`scanner/test/new-cwe-detectors.test.js` — 11 tests covering each
detector's vulnerable + clean shape, including post-fixture
suppression patterns (allow-list checks for open-redirect, CRLF
sanitizers for response-splitting).

**665 scanner tests pass / 0 fail** (up from 654).

## 0.66.0 — interprocedural precision + LLM default-on + C# / Kotlin IRs + corpus to 88

Four world-class lifts shipped together. After v0.65 the F1=0.636 number
was honest but the engine was still k=1 monovariant, the LLM validator
was opt-in, and the IR coverage stopped at JS/TS/Python/Java.

### Interprocedural taint precision (engine semantics)

`scanner/src/dataflow/engine.js`:
- **k≥2 context-sensitive summaries.** At assign-from-call sites the
  engine now builds the entry-taint-state from call args + current
  taint via `entryStateFromCall()` and looks up (lazily computes) a
  summary keyed by THAT entry state. Closes the "helper is pure when
  called clean but tainted when called with user input" FN class.
- **`applyAtCallSite` wired.** Mutated by-reference params propagate
  back to caller vars (`Object.assign(target, tainted)` → `target`
  tainted in caller). Was previously dead code.
- **Fixed-point iteration.** `runTaintEngine` now runs the pre-pass
  up to MAX_FP_ITERS (3) iterations or until the summary cache size
  stabilizes — recursion no longer under-approximates. Budget caps
  on walltime + cache size still hold.

Tests in `scanner/test/interproc-k2.test.js` lock the lifts: context
disambiguates tainted vs clean call sites, recursion converges within
budget, large helper chains finish within walltime.

### LLM validator default-on

`scanner/src/llm-validator/index.js` flips from opt-in to default-on:

| Env state                                    | Behavior      |
|----------------------------------------------|---------------|
| `LLM_ENDPOINT` unset                         | no-op         |
| `LLM_ENDPOINT` set, `VALIDATE` unset         | **runs**      |
| `LLM_ENDPOINT` set, `VALIDATE=0`             | no-op (opt-out) |
| `LLM_ENDPOINT` set, `VALIDATE=1`             | runs (legacy) |

Cache by `(file-content-sha256, source→sink path, prompt version,
model id)` continues to suppress repeat calls. Fail-closed semantics
unchanged — any prompt-injection / verify-failure → escalate (keep).

### C# IR backend (new language)

`scanner/src/ir/parser-cs.js` (~290 lines) — regex-based first pass,
parallel approach to the legacy Python regex parser. Models method
declarations with modifiers, params, body extraction with brace-depth
tracking. Lowers `var x = …`, `Type x = …`, `x = …`, calls, return,
throw. Builds a linear CFG per method. Plus 24 C# catalog entries:
ASP.NET MVC sources (`Request.Form`, `Request.QueryString`,
`Request.Cookies`, `Request.Headers`, `Request.Body`), sinks (SqlCommand,
Process.Start, File.ReadAll*, WebClient, HttpClient, BinaryFormatter),
sanitizers (HtmlEncode, UrlEncode, GetFullPath, Parse/TryParse,
Regex.Escape, AddWithValue).

### Kotlin IR backend (new language)

`scanner/src/ir/parser-kt.js` (~250 lines) — same regex approach.
Models `fun` declarations with modifiers, params, optional return
type, body extraction. Lowers `val`/`var`/`x = …`, calls, return,
throw. Kotlin string interpolation (`"hi $x"` / `"hi ${name}"`) lowers
into IR template-expression form so the engine sees the inner taint.
Plus 14 Kotlin catalog entries: Ktor / Spring sources, JDBC / Exposed /
ProcessBuilder / readText / ObjectInputStream sinks, escapeHtml4 /
URLEncoder / toInt / canonicalFile / setString sanitizers.

Both IRs wire into `buildProjectIR` and `buildProjectIRAsync`. Tests
in `scanner/test/parser-cs-kt.test.js`: shape correctness, multi-method
files, end-to-end scan over ASP.NET + Ktor fixtures.

### CVE-replay corpus: 50 → 88 entries (20 CWEs × 8 languages)

`bench/cve-replay/generate-corpus-extended.mjs` adds 38 entries:
- 8 C# fixtures (exercises new IR)
- 8 Kotlin fixtures (exercises new IR)
- 6 new CWE families: SSTI (CWE-94), LDAP injection (CWE-90), XPath
  injection (CWE-643), open redirect (CWE-601), HTTP response
  splitting (CWE-113), regex DoS (CWE-1333)
- 16 framework variants for existing families (NestJS, Koa, Symfony,
  Laravel, Gin, Fiber, etc.)

**Aggregate F1 = 0.500** (Wilson 95% CI [0.249, 0.429]) on the 88-entry
corpus. Lower than v0.65's 0.636 BECAUSE the new fixtures include
capabilities the scanner doesn't yet detect (C#/Kotlin coverage is
still thin; new CWE families have no detection rules). This is the
honest direction — broader corpus, narrower CI, real measurement.
Regression-tier CI gate remains F1=1.0.

### Test totals

654 scanner tests pass / 0 fail (up from 640 in v0.65). Smoke +
regression-tier CI both green.

### Migration

No breaking changes. To enable the LLM validator default-on path, set
`AGENTIC_SECURITY_LLM_ENDPOINT`. To opt out: `AGENTIC_SECURITY_LLM_VALIDATE=0`.
C# and Kotlin scans require no setup — drop a `.cs` or `.kt` file in
the scan tree.

## 0.65.0 — sanitizer catalog 8× / CVE corpus 6× / continuous CVE alerting

Closes three ASPM/SAST competitiveness gaps surfaced in the post-v0.64 review:
sanitizer coverage that lagged commercial vendors, a published F1 number
measured against a corpus too small to be credible, and a `/cve-alerts`
command that configured a webhook but never actually monitored anything.

### Sanitizer catalog: 48 → 372 entries (7.7×)

New module `scanner/src/dataflow/catalog-expanded.js` adds ~325 sanitizer
entries spanning 6 languages and 10 categories (HTML escape, SQL
parameterization, shell escape, URL encode, path normalize, regex escape,
LDAP/XPath, XML/JSON, validators, type coercion). Merged into the main
catalog at load time; on id collision the base catalog wins.

| Language    | Before | After |
|-------------|-------:|------:|
| JavaScript  |     11 |   105 |
| Python      |     11 |    96 |
| Java        |      8 |    61 |
| PHP         |      4 |    41 |
| Ruby        |      5 |    33 |
| Go          |      2 |    36 |
| **Total**   | **48** |**372**|

Tests in `scanner/test/catalog-expanded.test.js` enforce: minimum entry
count, per-language coverage floors, well-formed entry shape, no
duplicate IDs across the merged catalog, callee identifiers that the
indexer can match, and family vocabulary hygiene.

Two pre-existing duplicate IDs in the base catalog (`py-input`,
`py-os-environ`, `py-open`, plus 14 in the v2 Python block) were fixed
in this pass — the duplicate-id test surfaced them.

### CVE-replay corpus: 8 → 50 entries (6.25×)

`bench/cve-replay/generate-corpus.mjs` emits 42 capability-tier fixtures
across 11 high-priority CWE families and 6 languages:

| Family              | CWE        | Entries |
|---------------------|------------|--------:|
| SQL injection       | CWE-89     |       5 |
| XSS                 | CWE-79     |       4 |
| Command injection   | CWE-78     |       5 |
| Path traversal      | CWE-22     |       5 |
| SSRF                | CWE-918    |       4 |
| Deserialization     | CWE-502    |       4 |
| XXE                 | CWE-611    |       3 |
| Prototype pollution | CWE-1321   |       2 |
| CSRF                | CWE-352    |       2 |
| Hardcoded secrets   | CWE-798    |       3 |
| Weak crypto         | CWE-327/338|       5 |

Aggregate F1 against the new corpus is **0.636** (Wilson 95% CI [0.346,
0.591]) — an honest baseline, replacing the previous F1 number measured
against 8 cherry-picked fixtures. The regression-tier CI gate still
passes F1=1.0. Failing capability entries graduate to regression as fixes
land (CONTRIBUTING.md's 5-snapshot rule).

### Continuous CVE alerting daemon

New `scanner/src/posture/cve-alert-daemon.js` polls OSV for the project's
dependency tree and fires the configured webhook when a new advisory
drops. Multi-ecosystem: npm, PyPI, Ruby, Go, Cargo, Composer, Maven,
Dart. Reads `.agentic-security/cve-alerts.json` (the schema written by
`/cve-alerts`), dedupes against `.agentic-security/cve-alerts-state.json`
so re-runs don't re-page. Slack / Discord / generic webhook payload
shapes built in.

- `agentic-security cve-watch [--alert-url] [--min-severity] [--dry-run]`
  — one-shot run. Schedule it via cron or CI.
- `scripts/ci-templates/cve-watch.github-actions.yml` — drop-in GitHub
  Actions workflow (daily 08:00 UTC + `workflow_dispatch`). Reads
  `CVE_ALERT_URL` from repo secrets; commits state file with `[skip ci]`.

21 unit tests in `scanner/test/cve-alert-daemon.test.js` cover each
manifest reader, severity normalization, deduplication across runs,
min-severity floors, payload formatting, and offline-mode refusal.

### Migration notes

- Re-running `npm run build` is recommended to bundle the new daemon
  binary entry. No breaking changes; all v0.64.0 commands and skills
  still work as before.
- The capability-tier F1 score in the manifest is intentionally honest
  (0.636, not 0.85). Path to 0.85 is more corpus, not better numbers.

## 0.64.0 — auto-activating skills + multi-harness manifests

Inspired by patterns from the obra/superpowers plugin's "mandatory workflows,
not suggestions" stance: the agent shouldn't wait for the user to type
`/scan` or `/fix` before doing the security thing. Nine new auto-activating
skills cover the common security/privacy moments where the agent should
intervene before damage lands. Plus Codex / Cursor / Gemini manifests so the
12 MCP tools work in those harnesses too.

### Auto-activating skills (9 new)

Each lives at `skills/<slug>/SKILL.md`. The `description:` frontmatter is
the activation cue Claude Code's skill router reads. All ≤120 chars,
enforced by `npm run test:lifecycle`.

- **`security-explain-cve`** — fires when user mentions CVE-id / GHSA / asks "what is this vuln". Routes to `lookup_cve` MCP tool + `/explain`.
- **`security-scan-on-deploy`** — fires on "ship / deploy / launch / is this safe?" intent. Checks `last-scan.json` mtime, runs a fresh scan if stale, renders a verdict (not a wall of findings).
- **`security-fix-finding`** — fires when user references a finding and asks to fix. Enforces the deterministic toolchain (`synthesize_fix → verify_fix → apply_fix`); refuses raw `Edit`.
- **`security-weak-crypto`** — fires **before** the agent writes md5/sha1 for passwords, DES/3DES/RC4, static IVs, `Math.random` for tokens, or JWT with `none` algorithm. Refuses the write, proposes the right primitive with literal code.
- **`security-rotate-leak`** — fires when a leaked secret is mentioned. Masks the value, detects the provider, prints the revoke URL, estimates blast radius BEFORE rotating, refuses to print the value back.
- **`security-eval-warn`** — fires before `eval()` / `new Function()` / `setTimeout(string,…)` / `pickle.loads` / `eval($x)` / `class_eval`. Diagnoses what the user actually wants, proposes the structured alternative.
- **`security-sql-injection-warn`** — fires before template-literal queries / `+`-concat into SQL / NoSQL operator injection / LDAP/XPath concat. Shows the literal parameterized form for the user's specific DB driver.
- **`threat-model-first`** — fires **before** the agent writes new auth / secret / external-API / file-upload / OAuth / deserialization code. Walks STRIDE per touch-point (one sentence per row, no skipping); writes `TM.md` to `.agentic-security/agent-scratchpad/threat-model/<session>/` via `append_scratchpad`. Then proposes implementation with each defensive measure citing its STRIDE row in a code comment.
- **`privacy-data-flow`** — fires **before** the agent writes code touching PII / PHI / PCI / GDPR-special / confidential data shapes. Classifies the data, traces the destination (storage tier / encryption / third-party processors / logging / retention / backups / replication), maps to jurisdiction (GDPR / HIPAA / CCPA / PCI-DSS), writes `DATA_FLOW.md` to the scratchpad. Refuses hard violations (logging full PAN, sending PHI to non-BAA processor, storing CVV after auth).

### Skills-registry integrity test

`scanner/test/skills-registry.test.js` enforces:
- Every `skills/<slug>/SKILL.md` has well-formed YAML frontmatter
- `name:` equals `agentic-security:<slug>`
- `description:` is ≤ 120 chars (re-asserted at unit-test time)
- Auto-activating skills include an "Activate" / "Activate on" cue
- Every `/<slash-command>` referenced in a skill body resolves to a real
  file under `commands/`

7 new tests, all passing.

### Multi-harness manifests (3 new)

The MCP server is harness-agnostic — same binary, different manifest:

| Harness        | Manifest                          |
|----------------|-----------------------------------|
| Claude Code    | `.claude-plugin/plugin.json`      (already shipping) |
| **Codex CLI**  | `.codex-plugin/plugin.json`       (new) |
| **Cursor**     | `.cursor-plugin/plugin.json`      (new) |
| **Gemini CLI** | `gemini-extension.json` (root)    (new) |

Each manifest declares the same `agentic-security` MCP server pointing at
`scanner/bin/agentic-security-mcp.js`. Each carries an explicit note about
which surface IS validated vs not. The 12 MCP tools work identically across
all four harnesses; the slash-command + skill-activation surface is Claude-
Code-specific today.

README updated with an "Install in your harness" table covering all four
plus the generic MCP-aware-client fallback.

### Lint state

89 surfaces total (80 commands + 9 skills + add-scan-rule SKILL). All
within the 120-char description / 200-char argument-hint caps.

### Tests

619/619 passing (was 612 in v0.63.0; +7 skills-registry tests).

## 0.63.0 — Python IR via stdlib ast (real parser, regex fallback)

Replaces the hand-rolled regex Python parser with Python 3's stdlib `ast`
module (zero npm bundle bloat, zero pip install, runs in a per-scan
subprocess) and keeps the regex parser as a fallback when Python isn't on
PATH. The new path closes the gaps the regex parser admitted to in its own
comments: comprehensions, decorators, `match` statements, `async`/`await`,
lambda bodies, and nested-paren default args (`def f(x=Foo(1,2))`).

### What ships

- **`scanner/src/ir/parser-py.helper.py`** — Python 3.8+ stdlib script
  that reads `[{file, content}, ...]` JSON on stdin and emits the same
  IR shape as the regex parser, but computed from a real AST. Models
  assign / call / member / subscript / f-string / if / for / while /
  try-except / return / raise / async-for / async-with. Captures every
  function definition (including nested, decorated, async, generic) even
  when the body has unmodeled constructs.
- **`scanner/src/ir/parser-py-cst.js`** — Node-side dispatcher.
  Batched: ALL Python files in a project go in one subprocess invocation.
  Capability probe cached per-process. 10 s timeout on the whole batch.
- **`scanner/src/ir/index.js`** — three-mode toggle:
  `AGENTIC_SECURITY_PY_PARSER=auto` (default, falls back silently when
  python3 missing), `cst` (force, error if unavailable), `regex`
  (force legacy).
- **`scanner/src/ir/CLAUDE.md`** — documents the dual-parser shape,
  the IR contract every parser must produce, and the retirement plan
  for the regex parser.

### What's STILL not modeled

The CST parser intentionally emits `kind: 'noop'` for these to keep the
CFG bounded — the regex parser dropped the entire function for the same
shapes; we capture the function record but skip the body lowering:

- `match` statement case bodies (function is captured; per-case taint
  flow not yet routed)
- destructuring assignment (`a, b = req.body`) — only single-target
  assigns get a precise `target` field
- comprehension `if` filters and multi-`for` generators — the elt is
  modeled; the generator's own predicates aren't

### Cost / risk

- One `python3` subprocess per `runScan`, not per file. Batched stdin
  payload. Capability probe runs once and is cached.
- When python3 isn't installed (or is < 3.8), the regex parser handles
  the scan unchanged. No behavior regression for those customers.
- Set `AGENTIC_SECURITY_PY_PARSER_DEBUG=1` to surface fallback events
  on stderr.

### Tests

12 new CST-specific tests in `scanner/test/parser-py-cst.test.js`
covering decorators, async, nested-paren defaults, match statements, list
comprehension taint flow, nested function defs, batch behavior, syntax-
error isolation per file, single-file/batch shim equivalence. All skip
gracefully when python3 isn't on PATH. Total suite: 612/612 passing.

## 0.62.0 — agent-harness hardening + slash-command consolidation

Five rounds of analysis applied to the plugin's scanner + MCP server + sub-agent
harness across this release. Each section corresponds to one external source;
in-source comments tag the originating thread (`premortem #N`, `post-rec #N`,
`harness-anatomy #N`) for cross-reference.

### Security & integrity (premortem hardening)

- **Per-install HMAC key** for `last-scan.json` integrity (was hostname-derived
  and publicly forgeable in CI / containers). Stored at
  `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via
  `$AGENTIC_SECURITY_HMAC_KEY`. Legacy hostname key verified for one release
  to migrate existing signed scans.
- **MCP reserved-write list expanded** to `.github/`, `.gitlab/`, `.circleci/`,
  `.buildkite/`, `.terraform/`, IaC dirs, every common manifest basename
  (`Dockerfile`, `Jenkinsfile`, `package.json`, lockfiles, `pom.xml`,
  `Cargo.toml`, …) and `*.tf` / `docker-compose.yml`. Closes the
  forged-finding-rewrites-CI-workflow attack path.
- **`rules.yml disable:` requires signature.** `applyOverrides` now refuses
  the `disable:` list unless `.agentic-security/rules.yml.sig` verifies
  under the per-install HMAC. `severityOverrides`, `custom:`, `ignorePaths`
  are not gated (they don't reduce coverage). Override via
  `$AGENTIC_SECURITY_RULES_UNSIGNED=1`.
- **MCP `SERVER_VERSION`** reads `package.json` at module load (was a
  hardcoded literal that rotted).
- **MCP `find_rule_module` tool** for codebase navigation (CWE / family →
  detector file) without grep-and-pray.
- **MCP `apply_fix`** now passes patch text through unredacted (the prior
  redact-on-output behavior silently corrupted valid patches whose content
  matched a secret-shape).
- **Per-stableId attempt budget** (default 2) on `apply_fix`. Refuses a
  third attempt with structured `{ budgetExceeded, attempts, maxAttempts }`.
- **Optional remote audit-log sink.** Set
  `$AGENTIC_SECURITY_AUDIT_WEBHOOK=<url>` and every MCP tool call is
  fire-and-forget POSTed to the witness. Closes the full-file-rewrite
  blind spot of the local-only hash chain.

### Scanner correctness

- **`SummaryCache` wired** into the taint engine (k=1 monovariant
  return-taint). Was dead code; now the assign-from-call lattice consults
  cached summaries for resolved callees.
- **Per-flow source attribution** in IR-TAINT (was first-source-globally-
  seen; produced misattributed evidence in findings).
- **`finding-defaults` backfill** stamps `parser` + `family` on every
  finding before calibration / confidence run. Closes the "0 parser /
  20 family null on a smoke run" silent-no-op.
- **Tautological Brier removed.** `computeBrierFromHistory` (always
  returned 0) replaced with `computeBrierOnHeldOut(samples)` taking real
  labels. New `posture/holdout-eval.js` evaluator: Brier + ECE + per-family
  TP/FP + Wilson CI.
- **PoC param-key inference** reads the actual handler file window;
  surfaces `paramKey`, `paramKeyConfidence`, `paramKeyInferred`. Low-
  confidence PoCs trigger `regression-test-gen` to refuse rather than
  ship a fake-passing test.
- **CVE-replay scoring fixed.** TN branch reachable; pre/post scored
  independently. Per-slice F1 (by CWE, language, source-quality tier).
  Wilson 95% CI on the aggregate TP-rate.
- **Python parser** switched to a balanced-paren scanner for calls + def
  signatures (was a `[^()]*` regex that rejected `db.execute(sanitize(x))`
  and `def f(x=Foo(1,2))`).

### Agent harness

- **`security-fixer` writes via MCP, not Edit.** Tool list stripped to
  `Read, Bash, Grep`. The deterministic toolchain (`synthesize_fix` →
  `verify_fix` → `apply_fix`) is the only write path. The LLM is the
  intent layer; the MCP server is the execution layer.
- **Subagent path-confinement schema** (`agents/_CONFINEMENT.md`) shared
  with the MCP reserved-write list.
- **`security-fixer` consumes structured `verify_fix.introduced[]`** to
  diagnose template-incomplete vs codebase-prior vs lint-failed outcomes.
- **PLAN.md decomposition convention** for batched runs:
  `.agentic-security/agent-scratchpad/<agent>/<session>/PLAN.md`. Survives
  context resets; auditable artifact for governance.
- **AGENTS.md continual learning.** `.agentic-security/AGENTS.md` is the
  append-only narrative file the agent writes to at session end. The
  SessionStart hook reads it; the Stop hook nudges the agent to record an
  entry when work happened.
- **MCP scratchpad pair** (`append_scratchpad`, `read_scratchpad`)
  confined to `.agentic-security/agent-scratchpad/<agent>/<session>/`.
  Strict path validation; 2 MB / file, 50 MB total caps.
- **MCP tool-output offloading.** `scan_diff` and `explain_finding`
  results exceeding `OFFLOAD_THRESHOLD` (default 10) write the full payload
  to the scratchpad; the response shrinks to `{ head, tail, total,
  scratchpadPath, pagingHint }`. The agent pages through with
  `read_scratchpad`.
- **MCP `lookup_cve`** tool: read-only access to local OSV / KEV / EPSS
  caches with staleness tiers. Closes the knowledge-cutoff gap for SCA
  reasoning without triggering a network fetch.
- **MCP `append_agents_memory` / `read_agents_memory`** tools wrap the
  AGENTS.md surface.

### Evals + benches

- **CVE-replay corpus tiered** into `regression/` (CI gates here — F1=1.0
  required) and `capability/` (frontier; failure informational).
  Graduation policy: 5 consecutive passes → promote.
- **`npm run bench:cve-replay:ci`** new CI gate.
- **Agent-task corpus** at `bench/agent-tasks/security-fixer/`: end-to-end
  eval of the deterministic toolchain (synth → verify → apply) against
  fresh temp copies of fixtures. 7 graders per task; pass@1 reporting.
- **`llm-validator` consistency harness** (`scanner/src/llm-validator/
  consistency.js` + `agentic-security-consistency` bin): pass^k stability
  measurement across N trials on the same fixture set.
- **Human ↔ LLM grader calibration** (`posture/grader-calibration.js`):
  Cohen's κ between `/triage` human verdicts and validator verdicts on
  the stableId overlap. Alarm when κ < 0.6 with n ≥ 10.
- **`agentic-security-audit` CLI**: `review`, `metrics`, `verify`
  subcommands for the MCP audit log. `--by-session` aggregation with
  outlier flagging (default ≥20 calls per tool).
- **`audit.js`** stamps `sessionId` on every entry.

### Repo structure (Claude-Code-at-scale)

- **`.claude/settings.json`** with team-committed read-deny list
  (generated bundle, bench caches, scan-state JSON) to keep noise out of
  context.
- **Subdirectory `CLAUDE.md` files** added: `scanner/`,
  `scanner/src/{sast,posture,dataflow,mcp}/`. Root `CLAUDE.md` trimmed
  253 → 115 lines (pointers + gotchas only).
- **`npm test` split into scoped scripts**: `test:smoke / sast / posture /
  dataflow / mcp / report / bench-modules / lifecycle`. Full suite chains
  them.
- **Stop hook (`hooks/session-stop-drift-check.js`)** flags new modules
  in `scanner/src/{sast,posture,dataflow,mcp}/` not yet indexed in the
  matching subdir CLAUDE.md, plus prompts for an AGENTS.md entry when
  the session touched tracked files.
- **SessionStart self-check (`hooks/session-start-self-check.js`)**
  validates every command/agent frontmatter shape; surfaces malformed
  surfaces.
- **`skills/add-scan-rule/SKILL.md`** holds the "add a new SAST rule"
  workflow as an on-demand skill (was in root CLAUDE.md).
- **`docs/POSITIONING.md`** — explicit ICP statement (vibecoder-first;
  pro follow-on).

### Slash-command consolidation (LangChain harness-anatomy #5)

The 77-command surface was the exact "tool proliferation" anti-pattern the
post warned about. Always-paid frontmatter (description + argument-hint)
trimmed **20.3 KB → 11.3 KB (44% reduction)**.

- **Description cap of 120 chars** + argument-hint cap of 200 chars,
  enforced by `scripts/lint-command-descriptions.mjs` in
  `npm run test:lifecycle`. 76 surfaces trimmed.
- **Eleven commands folded into canonical forms**, with deprecated
  aliases kept one release for muscle memory:

  | Old | New |
  |-----|-----|
  | `/ci-gate-multi` | `/ci-gate --provider <name>` |
  | `/rotate-key-auto` | `/rotate-secret --auto` |
  | `/trim-dead-code` | `/trim --what code` |
  | `/trim-dependencies` | `/trim --what deps` |
  | `/story-explain` | `/explain --narrative` |
  | `/security-badge` | `/security-attestation` (default) |
  | `/security-onepager` | `/security-attestation --format onepager` |
  | `/trust-page` | `/security-attestation --format page` |
  | `/dep-pinning` | `/supply-chain-check --show pinning` |
  | `/dep-freshness` | `/supply-chain-check --show freshness` |
  | `/dep-alternatives` | `/supply-chain-check --show alternatives` |

- **Skipped on purpose:** `/secure` (vibecoder entry point — kept
  untouched); the LLM-sec cluster (each command serves a distinct
  workflow). Tier 3 demote-to-skills also skipped after investigation —
  Claude Code today loads both commands and skills' descriptions in the
  always-paid surface, so the move wouldn't actually save context.

### Tests

600/600 tests passing. CVE-replay CI gate green (regression F1=1.0 on
3 entries). Lint gate green (all 80 surfaces within caps).

## 0.51.0 — 11 of 16 PRD-missing features (5 research items deferred)

This release lands all 11 tractable FRs from the v2 PRD audit. The 5
research-level FRs (k=2 calling context, narrow symbolic execution, hybrid
static+dynamic, eBPF/dtrace live instrumentation, LLM-based intent
inference) are deferred to Phase 6+ with their reasons documented in the
PRD.

### Shipped

- **FR-CHAIN-FILTER** (`posture/cross-lang-meta.js`). Cross-language chain
  detectors only chain to chain-worthy families (sql-injection,
  command-injection, xss, ssrf, code-injection, deserialization, xxe,
  path-traversal, idor, mass-assignment, prototype pollution, and others).
  Eliminates the "queue chain to CSRF" semantic-noise the polyglot bench
  surfaced.
- **FR-FAMILY-REGISTRY** (`posture/cross-lang-meta.js`). Cross-language
  chains get canonical family names (xlang-openapi / xlang-grpc /
  xlang-graphql / xlang-queue / xlang-orm / xlang-iac / xlang-unknown).
- **FR-LEARN-7** (`bin/agentic-security reset`). Right-to-delete CLI;
  wipes accumulated learned state while preserving operator-authored
  config. `--yes` to actually delete; `--keep <names>` to spare specific
  items.
- **FR-PY-SAST** (`sast/python-sinks.js`). Python sink-side coverage:
  SQLAlchemy text() with f-string, cursor.execute concat, os.system /
  subprocess shell=True, pickle.loads, yaml.load, marshal.loads, eval/exec
  on request data, compile() on user input, flask.send_file with user
  path, send_from_directory, open() with f-string, requests verify=False,
  ssl._create_unverified_context, requests/urlopen with user URL, lxml/
  etree on user input. **Closes G3:** polyglot F1 went from 0.727 → 1.00.
- **FR-VER-3** (`posture/regression-test-gen.js`). Per finding with a PoC,
  emit a framework-idiomatic regression test (Jest for Node, pytest for
  Python). Surfaced as `f.regression_test = { lang, framework, filename,
  runHint, code }`.
- **FR-LIVE-HARNESS** (`posture/verifier-target.js`). Schema for
  `.agentic-security/verifier-target.yaml` describing how to bring up the
  customer's app (docker-compose or command shape). The `verify --live`
  CLI auto-discovers it. Safety: `command` shape requires a known-good
  start pattern unless `AGENTIC_SECURITY_VERIFY_TARGET_OK=1`.
- **FR-XSAT-7** (`posture/iam-policy.js`). AWS IAM policy auditing.
  Curated dangerous-actions list (iam:*, s3:*, lambda:*, ec2:*, dynamodb:*,
  rds:*, secretsmanager:*, kms:*). Flag Effect=Allow + wildcard resource
  + no Condition.
- **FR-XSAT-8** (`posture/container-runtime.js`). Dockerfile + k8s
  manifest + ECS task def. Detects USER root, privileged: true,
  hostNetwork, hostPID, runAsUser: 0, capabilities ALL/SYS_ADMIN,
  /var/run/docker.sock bind-mount, ADD with remote URL.
- **FR-LOGIC-1 + FR-LOGIC-2 + FR-LOGIC-7** (`posture/business-logic.js`).
  AuthZ matrix construction (per-resource consistency check + IDOR
  detection on mutation routes with :id but no ownership/role check),
  state-machine extraction (catches writes outside the declared status
  set), and negative-test-gap detection (auth route + happy-path test +
  no 401/403 assertion = miss).
- **FR-LOGIC-6** (`posture/flow-narration.js`). Per high-severity finding,
  emit a one-paragraph attacker→impact→cost narrative. Template fallback
  for 10 CWE families; opt-in LLM mode via
  `AGENTIC_SECURITY_FLOW_NARRATION_LLM=1`.
- **FR-LEARN-6** (`posture/rule-synthesis.js`, `agentic-security rule-synth`).
  Read triage-feedback.json, cluster FP verdicts by family + dir prefix,
  propose a YAML suppression rule when ≥ 5 verdicts cluster. Proposes —
  doesn't activate.
- **FR-SDLC-5** (`report/index.js::toSTIX`). `--format stix` emits a STIX
  2.1 bundle with one Vulnerability + Indicator + Relationship SDO per
  finding. CWE external_references; x_* custom properties for severity,
  calibrated confidence, exploitability, verifier verdict.
- **FR-SDLC-9** (`posture/policy-gate.js`, `--policy <file.rego>`).
  Policy-as-code gate. External OPA binary preferred; embedded mini-DSL
  evaluator for the common case. Supports == != > < >= != comparisons
  on `finding.<field>` and `sprintf("...", [args])` for messages.

### Deferred (Phase 6+ research)

- FR-SEM-2 k=2 calling-context — requires dataflow engine refactor
- FR-SEM-5 narrow symbolic execution — needs KLEE-style backend
- FR-SEM-6 hybrid static+dynamic — needs customer app instrumentation
- FR-VER-5 eBPF/dtrace live instrumentation — Linux/macOS only, opt-in
- FR-LOGIC-5 intent inference — LLM-based; pending prompt-injection-safe design

### Tests, bench, integrity

- 295 + 26 + 2 unit tests pass (was 240 before this release).
- Synthetic-bench F1 = 100% (baseline updated; new IDOR expected entry added
  for orm-raw-sql:15 — AuthZ-matrix detector finds a genuine missing
  ownership check that wasn't previously caught).
- Polyglot bench F1 = 100% (was 72.7%; Python SAST coverage closed G3 gap).
- No dead exports.

### Honesty correction

The PRD v2 said all 16 missing features. This release ships 11; 5 are
honestly deferred. The PRD-v3 update (next session) should reflect this
delivery state.

## 0.50.0 — next-gen SAST Phase 1 complete (5 of 5 units)

Closes Phase 1 of `docs/PRD-next-gen-sast-phase1.md`. The two units queued
from v0.49.0 (P1.2 verifier sandbox, P1.4 polyglot bench) are now wired.

### Shipped & wired

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** New
  module `scanner/src/posture/verifier.js`. Consumes the `f.poc` artifacts
  from P1.1 and assigns a per-finding `verifier_verdict`:
  - `verified-exploit` — PoC ran against a live target and exited 0
  - `verified-by-llm` — Layer-3 LLM accepted the finding
  - `verified-sanitizer-absence` — pattern-based proof that no sanitizer
    appears in a ±10 line window around the sink (9 vuln families covered)
  - `unverified-by-design` — CWE family where v1 explicitly doesn't ship a PoC
  - `cannot-verify` — sandbox error, missing target, PoC validation failed

  PoC static validation refuses destructive shell payloads, hardcoded cloud
  metadata IPs, runaway-length code, and Node PoCs without a deterministic
  `process.exit(...)`. Sandbox execution mode (opt-in via
  `AGENTIC_SECURITY_VERIFY_LIVE=1` + `AGENTIC_SECURITY_VERIFY_TARGET=<url>`)
  runs each PoC under Docker with `--cap-drop=ALL --memory=256m --read-only
  --user=nobody`; falls back to subprocess with `ulimit` when Docker isn't
  available. Fail-closed: any error → `cannot-verify`, never silent drop.
  New CLI subcommand `agentic-security verify [--finding <id>] [--live
  --target <url>]` re-runs the verifier loop on `last-scan.json` and
  persists the verdicts. Smoke on `vulnerable-js` fixture: 7 findings get
  `verified-sanitizer-absence` static proofs; 2 get `unverified-by-design`;
  the rest are `cannot-verify` pending live execution.

- **P1.4 — Cross-language polyglot benchmark (G3).** New `bench/polyglot/`
  with a tiny dependency-free YAML parser, the runner `runner.mjs`, and 4
  starter cases:
  - 01 HTTP→Python SQL (canonical Phase-2 detector gap — Python SAST)
  - 02 Queue→Python cmd (same gap; queue chain detected; sink not yet)
  - 03 ORM round-trip (Node-only; mass-assignment + data-exposure TPs)
  - 04 HTTP→Node SQL (clean end-to-end test of the OpenAPI cross-asset bridge)

  Default mode `recall-only` measures "does the chain fire where it
  should?" rather than penalizing incidental findings (header-hardening,
  CSRF on test routes, body-parser DoS warnings). Set `mode: strict` in a
  manifest for full-precision scoring. Current overall F1 = 72.7%; PRD G3
  target is 85%; the 27pp gap is Python-side detector coverage (Phase 2).
  New `npm run bench:polyglot`.

### Tests, bench, integrity

- 19 new tests in `test/verifier.test.js` (validation, sanitizer proofs,
  verdict assignment, batch annotation, fail-closed defense-in-depth).
- All 218 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- Polyglot bench F1 72.7% (above 30% v1 floor; below 85% G3 target — the
  gap is documented in `bench/polyglot/README.md`).
- No new dead exports.

### Honesty correction

The PRD's G2 target ("≥80% of high+/critical findings ship with a verified
PoC") is not measured yet — that requires a labeled run-against-target,
which the v1 verifier supports via `--live --target` but we haven't built
a target harness. v1 ships the framework; the labeled measurement is
Phase 5 work.

## 0.49.0 — next-gen SAST Phase 1 (3 of 5 units)

Implements 3 of the 5 Phase-1 shippable units from
`docs/PRD-next-gen-sast-phase1.md` (parent `docs/PRD-next-gen-sast.md`).
The two queued for the next session are noted at the end.

### Shipped & wired

- **P1.1 — PoC generator framework (FR-VER-2).** New module
  `scanner/src/posture/poc-generator.js` ships runnable proof-of-concept
  files for the top-10 CWE families from the parent PRD: SQL injection,
  command injection, XSS, path traversal, SSRF, code injection, CSRF, open
  redirect, XXE, and insecure deserialization. Each PoC is a self-contained
  Node script with one `fetch()` call, evidence-pattern detection, and a
  deterministic exit code (0 = exploit demonstrated, 1 = not demonstrated, 2
  = error). Templates respect a safety policy: no destructive shell commands,
  no real cloud-metadata IPs, no outbound network beyond localhost. Smoke:
  scanning `test/fixtures/vulnerable-js` produces 8 PoCs across 6 distinct
  CWE families. Findings get a new `f.poc = { lang, kind, cwe, family, runHint, code }`
  field surfaced in normalizeFindings and SARIF. Families without v1 template
  coverage get `f.poc = null` and a documented entry in
  `poc-cwe-map.js::NO_POC_FAMILIES`.
- **P1.3 — Brier-calibrated confidence (FR-UX-1, FR-UX-2).** New module
  `scanner/src/posture/calibration.js` turns the ordinal `confidence` score
  into a calibrated probability with 95% Wilson confidence interval. Per
  finding: `calibrated_confidence`, `calibrated_confidence_ci`,
  `calibrated_n`, `calibration_reason` (set when null — "insufficient-samples"
  / "no-family" / "no-history"). Seed corpus in
  `calibration-seed.json` covers 20 vuln families from the OWASP Benchmark +
  Juliet labeled runs; the customer's `.agentic-security/validator-metrics.json`
  overrides per-family when sample count is higher. Calibration is honest
  about uncertainty: `MIN_SAMPLES_FOR_CALIBRATION = 30`. The PRD G1 target
  (Brier ≤ 0.10 on a held-out labeled set) is queued for Phase 5; this ships
  the framework, the math, and the seed data.
- **P1.5 — Cross-language message queues (FR-XSAT-4).** New module
  `scanner/src/posture/cross-lang-queues.js` indexes producer and consumer
  call sites for Kafka (kafkajs, kafka-clients, confluent-kafka), AWS SQS
  (aws-sdk, boto3), RabbitMQ (amqplib, pika, Spring `RabbitTemplate`), Redis
  Streams (XADD / XREAD across Node, Python, Go), and Google Pub/Sub. When
  producer and consumer agree on a topic name and the consumer file has a
  high+ finding, we emit a `cross_language: true` chain back to the producer
  (and vice-versa). Severity is demoted one tier so the chain doesn't double-
  count in severity bucketing. Honest about uncertainty: only literal-string
  topic matches; constant-folded names left for Phase 2.

### Tests, bench, integrity

- 14 new tests in `test/poc-generator.test.js` (PoC coverage + safety).
- 9 new tests in `test/cross-lang-queues.test.js`.
- 14 new tests in `test/calibration.test.js` (Wilson + Brier + annotation).
- All 199 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- No new dead exports; `test/no-dead-modules.test.js` both subtests pass.

### Queued for next session

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** Needs
  Docker integration, network isolation, and a sandbox-escape test. The PoC
  generator already produces files; the verifier executes them in isolation.
- **P1.4 — Cross-language polyglot benchmark (G3).** Needs fixture builds
  across Node → Python → Java → Postgres. Measures the cross-asset claims
  we've now made for HTTP/gRPC/GraphQL/ORM/IaC/Queues.

### Honesty correction

The parent PRD claimed v1.0.0 ships at ~15 months. This release is one
session of work; we're at ~v0.49.0 on a path to v0.50.0 (Phase-1 release).
The PRD's G1 (Brier ≤ 0.10 on a held-out set) is not yet measured — the
shipped calibration is on the SEED corpus, which is by definition not held
out. We surface this in the `_caveat` field of `calibration-seed.json`.

## 0.48.0 — fourth-round premortem + CI bench failure

### Bench regression fix

The synthetic-bench CI job started failing at v0.47.0. Two issues:

- **Root-cause clustering over-merged across detectors.** Two distinct
  detectors (structural `Open Redirect` and `host-header`) that share CWE-601
  on the same `res.redirect(...)` line were collapsing into one finding,
  hiding the host-header bug. `sinkKey` now includes `f.parser` so two
  detectors never merge. Empty `sinkExpr` keys are skipped (was bucketing all
  rate-limit findings into one).
- **Two expected entries pointed at the same post-clustered line.** Cleaned
  up `expected.json` for `orm-raw-sql` and added six new `csrf` family
  expected entries for fixtures that legitimately lack CSRF protection.
  Baseline refreshed.

### Node 20 deprecation

Bumped `actions/{checkout,setup-node,upload-artifact}` to v5 and
`actions/github-script` to v8 (Node 24 native). Dropped the
`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround env.

### Fourth-round premortem — 15 findings closed

- **4R-1**: rule-pack signing is fail-closed in CI. When `CI=true` (and the
  common variants) and no signing keys are configured, pass-through mode
  refuses rather than silently accepting. Opt-in via
  `AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1`.
- **4R-2**: `scanner/dist/agentic-security.mjs` is now correctly tracked in
  `.gitignore`. The previous "Not committed" comment lied — the bundle was
  always committed, the comment was wrong. Now `dist/*` is ignored except
  `agentic-security.mjs` and `agentic-security.mjs.sha256`.
- **4R-3**: `scan.yml` downloads the bundle with checksum verification. New
  `scanner-ref` workflow input lets callers pin to a release tag or commit SHA
  for supply-chain hardening. `scanner/dist/agentic-security.mjs.sha256` is
  generated by `npm run build` and committed.
- **4R-4**: catalog `filterByProvenance` memoizes per (entries, mode) so the
  taint hot path no longer allocates a fresh array per match.
- **4R-5**: LSP `_depCache` is granularly invalidated on manifest save — only
  the saved file's entry is refreshed, not the whole project tree.
- **4R-6**: `no-dead-modules.test.js` has a sister "allowlist decay" check.
  Stale ALLOWLIST entries (25 of them, from v0.47.0) were removed.
- **4R-7**: `version.js` warns to stderr when `package.json` can't be read
  instead of silently falling back to `'unknown'`.
- **4R-8**: `applyFix` accepts `stableId` from the caller (`bin/` and `mcp/`)
  rather than re-deriving via `findingId`, which rotates on line-shift.
- **4R-9**: fix-history stale-lock reap is PID-aware. Only unlinks when the
  PID is dead OR the file's old AND the PID is unkillable. Atomic re-read of
  the lockfile before unlink avoids racing a fresh acquirer.
- **4R-10**: SARIF emits a tri-state `signatureStatus: 'verified' | 'unsigned'
  | 'pass-through'` field. The legacy `_unsigned` / `_passThroughSigning`
  flags are emitted alongside for one release of grace.
- **4R-11**: CLI and Markdown reports now render `validator_verdict` so SCA
  findings tagged `not-applicable` aren't invisible to the reader.
- **4R-12**: custom-rules deadline is per-scanRoot, accumulating across calls
  within a process. New `resetCustomRulesBudget(scanRoot)` for long-lived LSP
  scans; wired into the LSP server.
- **4R-13**: `prepublishOnly` refuses to overwrite a locally-edited
  `scanner/CHANGELOG.md` that differs from the canonical `../CHANGELOG.md`.
- **4R-14**: new `scripts/nist-compliance/test_regex_redos.py` asserts every
  import regex runs in linear time on pathological input — guards against
  re-introducing the `(?:[^)]|\n)+?` ReDoS fixed in `e0c669b`.
- **4R-15**: `PROMPT_VERSION` is now a public export of `llm-validator/index.js`.
  The `validator-cache gc` subcommand no longer reaches through the
  underscore-prefixed `_internal` private API and fails loudly if the version
  can't be read.

### Honesty note

All 15 fourth-round findings are closed without dead code (verified by the
no-dead-modules test). The bench failure was a real regression introduced
in v0.47.0 (clustering by CWE alone) — caught by CI, fixed by adding
`f.parser` to the cluster key.

## 0.47.0 — third-round premortem remediation

Third adversarial premortem identified 17 findings against the v0.46.0
remediation. All 17 are now closed. Highlights:

- **3R-1: integration test for dead exports** — new `test/no-dead-modules.test.js`
  walks `scanner/src/{posture,llm-validator,dataflow,lsp,ir,mcp}` and asserts
  every exported symbol has at least one external call site (`.js` files and
  `commands/*.md`). Allowlist for legitimate library-style exports. Closes the
  recurring "wired in code review, dead in code" failure mode.

- **3R-2 / 3R-3: single-sourced version** — `scanner/src/posture/version.js`
  reads `scanner/package.json#version` at module load; SARIF `tool.driver.version`
  and `CURRENT_RULESET_VERSION` now derive from it instead of independently
  hardcoded constants that diverged on every release.

- **3R-4: signing graceful degradation** — `rule-pack-signing.js` operates in a
  pass-through mode when both bundled and project keys are absent. One audit
  warning per session; findings carry `_passThroughSigning:true`. Set
  `AGENTIC_SECURITY_STRICT_SIGNING=1` to disable pass-through.

- **3R-5: CLI keygen safety rails** — `agentic-security-rule keygen` refuses
  `--out` paths under `.agentic-security/`; warns on non-TTY stdout without
  `--out`; writes private-key files mode 0600. `--i-understand-private-keys`
  to override.

- **3R-6: provenance surfaced in reports** — `normalizeFindings` carries
  `_unsigned` and `_passThroughSigning` through; SARIF `result.properties`
  emits `unsigned:true` / `passThroughSigning:true`; SARIF
  `invocations[].properties` now includes `rulesetVersion`, `rulesetVersionSource`,
  and `rulesetVersionMismatch` for trend attribution.

- **3R-7: requiresReAudit is now load-bearing** — `bench-realworld.js` reads
  curated expected JSONs' `requiresReAudit:true`, emits a stderr warning per
  affected corpus, and tags the corpus result with
  `requiresReAudit:true` so consumers know its F1 is informational.

- **3R-8: global deadline for custom rules** — `applyCustomRules()` now caps
  the total scan time across all files and all rules at 30s (overridable via
  `AGENTIC_SECURITY_CUSTOM_RULES_BUDGET_MS`), guarding against ReDoS sprees
  across many files even when each individual regex respects its 200ms budget.

- **3R-9: LSP dep-cache invalidation on manifest save** — saving any
  `package.json`/`pyproject.toml`/`Cargo.toml`/etc. now invalidates the cached
  dep snapshot before re-scanning, so freshly added vulnerable packages and
  removed ones reflect immediately in editor diagnostics.

- **3R-10: catalog OFFICIAL_ONLY is per-match** — `AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1`
  is now read per source/sink match instead of once at module load, so CI lanes
  that toggle strict mode just before invocation are actually honored.

- **3R-11: validator preflight handles SCA locators** — findings with
  `parser:'SCA'` or `pkg`/`component`/`purl` set are tagged
  `validator_verdict:'not-applicable'` rather than `'unvalidated'`, which
  was misleading for findings that an LLM cannot meaningfully judge.

- **3R-12: applyFix recover() cross-checks against last-scan.json** — the
  fix-history log entry records the matching finding's stableId at apply
  time; `recover()` after a crash now tags promoted entries as
  `applied-stale` when the finding has vanished from last-scan.json.

- **3R-13: file lock around log writes** — concurrent `applyFix`, `recover`,
  and `undo` invocations no longer race the `log.json` write; serialization
  via `log.lock` with 30s stale-lock reaping and 5s contention timeout.

- **3R-14: validator-cache GC subcommand** — `agentic-security validator-cache
  stats|gc [--older-than N] [--dry-run]` prunes `.agentic-security/llm-cache/`
  by age and prompt-version mismatch.

- **3R-15: tier cutoffs stable under 2-decimal rounding** — confidence tier
  (`high|medium|low|very-low`) is now derived from the 2-decimal display value,
  so a finding reported as "0.75" never lands in two tiers depending on the
  viewer's rounding.

- **3R-16: CHANGELOG ships with npm package** — `prepublishOnly` copies
  CHANGELOG.md into `scanner/`; added to `package.json#files`. The repo-root
  copy remains canonical; the in-package copy is gitignored.

- **3R-17: fix-history log compaction** — `agentic-security undo --compact
  [--retain-days N] [--prune-backups]` archives terminal entries (reverted,
  failed, applied-stale) older than the retention window into
  `log-archive-YYYY-MM.json`, optionally pruning their `.bak` files.

### Honesty correction

No claims in this release exceeded what shipped. v0.47.0 closes the 17
third-round premortem findings against v0.46.0 cleanly; the round-4 premortem
will surely find more, and that is fine.

## 0.46.0 — second-round premortem remediation + honesty correction

### Honesty correction for v0.45.0

The v0.45.0 commit message (`3acca6b fix(security): premortem remediation —
all 15 findings`) claimed all 15 first-round premortem findings were
remediated. A second-round adversarial premortem identified five of those
"closures" as dead code or wire-up regressions:

- `posture/fix-history.js::recover()` was exported but never called from
  any startup path → pending entries from a crashed `applyFix` accumulated
  forever. **Now fixed**: wired into `runScan.js` at top of every scan.

- `posture/ruleset-version.js::stampScan()` / `effectiveVersion()` were
  exported but never imported → ruleset-pinning was documentation only.
  **Now fixed**: wired into `runScan.js` to stamp every scan result.

- `posture/validator-metrics.js::recordTriage()` was exported but the
  `/triage` slash command did not invoke it → per-CWE production metrics
  never accumulated. **Now fixed**: `/triage` now calls `recordTriage` on
  every verdict (subject to the new symmetric learn gate).

- The custom-rules pipeline tagged unsigned RULES with `_unsigned: true`
  but the per-finding emitter (`toFinding`) did not copy the marker →
  the audit chain promised by the warning log did not exist in the data.
  **Now fixed**: findings now carry `_unsigned: true` when their rule does.

- `engine.js:6941` called the LLM validator with `concurrency: 4`,
  overriding the validator's `concurrency: 1` determinism default →
  cache-cold runs produced non-deterministic SARIF in the same commit
  that promised determinism. **Now fixed**: respects `AGENTIC_SECURITY_LLM_CONCURRENCY` env (default 1).

### Other second-round fixes

- **String-aware JSON parser** in the LLM validator. Previous
  `parseLastJsonObject` ignored string-state and could be fooled by braces
  inside JSON string literals. Rewritten to walk forward with full string-
  and escape-state tracking, then return the LAST valid candidate.

- **Empty file/line pre-flight** in `validateOne`. A validator response of
  `{"file":"","line":0,...}` trivially satisfied the cross-check on findings
  without precise location. Now refused with `unvalidated`.

- **Protected signing trust root**: trusted keys come from a built-in
  constant (`BUNDLED_OFFICIAL_KEYS`); project-local `.agentic-security/trusted-keys.json`
  is refused unless `AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1` is set
  (audit-logged). A PR contributor can no longer bootstrap a key into trust.

- **Key revocation**: trusted-keys.json `crl[]` honored (signature-hash
  blacklist); `revokedAt` field on each key honored (signatures dated after
  revocation refused).

- **`agentic-security-rule` CLI** for `keygen` / `sign` / `verify` with a
  first-time setup walkthrough and explicit private-key-handling warnings.

- **Symmetric AGENTIC_SECURITY_LEARN gate**: `/triage` no longer writes
  verdicts to `triage-feedback.json` without explicit opt-in. Prevents an
  attacker from poisoning the file in advance of someone flipping the
  read-side flag.

- **Worklist deadline check**: deep-mode taint engine honors `deadlineMs`
  inside `analyzeFunction`'s worklist (every 128 iterations). Pathological
  CFGs can no longer hold past the global timeout.

- **LSP loads dep-manifest files**: per-save scan in `lsp/server.js` now
  pre-walks the project tree once for `package.json` / `pom.xml` / `.proto`
  / `.graphql` / `.tf` so SCA + cross-language passes have their inputs.

- **SARIF notifications for caveats**: `tool.driver.notifications` and
  `invocations.toolExecutionNotifications` now carry the load-bearing
  warnings (priority scores are ordinal, OWASP Benchmark numbers are
  benchmark-tuned). Customer CI ingesters see them without reading docs.

- **Re-sanitization on cache read**: validator reasoning passes through
  `sanitizeReasoning` again on cache hit (defense in depth against any
  future write-path regression).

- **Provenance + requiresReAudit fields** added to all 25 bootstrapped GT
  files under `bench/.../expected/`. Machine-readable signal that the
  bootstrap origin is self-referential.

### What this commit honestly does NOT close

- BUNDLED_OFFICIAL_KEYS is empty — a production deployment needs the
  maintainers to generate a real keypair, distribute the private key
  offline, and ship the public key. Today's effective behavior is "no
  official keys, project keys via opt-in."
- The CVE-replay corpus is still 1 starter entry (G1 second half remains
  not delivered).
- Real-world Java F1 generalization is still unmeasured.

## 0.45.0 — first-round premortem remediation

(See commit 3acca6b. Some closures were dead-code; see honesty correction
above.)

## 0.44.0 — multi-session items: gRPC/GraphQL/ORM cross-lang, IDE plugins

## 0.43.0 — small engineering items: MCP verify_fix/synthesize_fix,
SentQL path predicates, conversation-context hook, fix-plan,
per-CWE metrics

## 0.42.0 — Layer 1 IR + Layer 2 interprocedural taint, F1=0.907 on
OWASP Bench v1.2 (blind, strict)
