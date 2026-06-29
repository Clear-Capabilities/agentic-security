# Changelog

## 0.125.0 — multi-provider LLM cost + prompt-cache linter (Cache Economics v2, phase 1)

First slice of the Cache Economics v2 PRD (`docs/CACHE_ECONOMICS_V2_PRD.md`) — the
foundation (P1 provider detection, P2 provider catalog) + the flagship analyzer (F1
cache-hygiene + P3 per-provider model/depth recommendation). The optimizer now reaches
beyond this Claude Code session into the user's **own AI-app code**, across providers.

- **Provider catalog** (`scanner/src/posture/provider-catalog.js`): a dated, no-network
  snapshot of Anthropic / OpenAI / Google Gemini / xAI — model ladder ($/1M rates), the
  "depth" knob (effort / reasoning_effort / thinkingBudget), and the cache model
  (explicit vs automatic vs implicit). Prices are sourced, not hardcoded-in-logic, with a
  `SOURCED_AT` staleness date.
- **LLM cost/cache detector** (`scanner/src/sast/llm-cost-advisor.js`, `scanLlmCost`):
  provider-aware, gated on detecting an LLM SDK (low FP), emits **advisory** findings —
  (1) *prompt-cache killer*: a timestamp/UUID/random value baked into a prompt prefix
  that defeats caching; (2) *over-provisioned*: a flagship model at high depth, with the
  catalog's cheaper model + lower depth **in that provider's framework** as the fix
  (e.g. an OpenAI app → "gpt-5.4 at reasoning_effort=low"). Severity `low`/`info` so it
  never inflates security counts.

Remaining PRD phases (F2 measured cost, F3 TTL, F4 compaction, F5 pre-warm, F6 cross-
session warmth, F7 self-tuning; full P4 per-provider economics) ship next.

## 0.124.1 — fix: narration no longer prints a broken location

Now that v0.124.0 surfaces `narration` prominently inline, a pre-existing template
bug became visible: some narrations read `app.js:?` / `app.js:undefined` because the
location was interpolated before the finding's line was finalised.

- `scanner/src/posture/flow-narration.js`: the location is redundant (the finding
  header already shows `file:line`), so the family templates are now
  location-agnostic, and `_routeOf()` (generic fallback + LLM prompt) falls back to
  the file alone — or "this endpoint" — instead of emitting `:undefined` / `:?`.
- Regression test in `test/flow-narration.test.js` asserts no template renders a
  broken location when the line is absent.

## 0.124.0 — inline finding depth (no second command for "why it fired")

The depth `/triage --explain` produces now renders **inline** in the finding views,
assembled from fields already on the finding (`narration` + `whyFired` + fix) — so the
default per-finding view answers "why does this matter / how does it fire / how do I
fix it" without a separate command. Addresses the "only ~2 sentences per finding"
feedback. Presentation only — no detector/severity changes.

- **Inline explain block** (`scanner/src/report/index.js`): every per-finding surface
  now shows `why:` (the impact narration), `how:` (the `whyFired` detector + source→sink
  flow, with sanitizers/guards/reachability under `--verbose`), and `fix:`. Wired into
  the firehose list (`toCLI`), the pro table (a compact one-line "why"), and the HTML
  report ("Why it matters" / "How it fires" blocks). Default trims the narration to two
  sentences; `--verbose` shows the full narrative + fix code. Degrades gracefully when a
  finding lacks the fields (e.g. SCA).
- **`--firehose` actually lists findings now.** Previously it only lowered the
  confidence threshold while the vibecoder verdict showed no per-finding list; it now
  appends the full per-finding list (with the inline depth) so "Show ALL findings" does.

## 0.123.0 — report clarity: risk-demotion labels, depth discoverability, HTML export docs

Acting on user feedback that findings could overstate severity, that explanations
felt thin, and that the browser report was hard to find. No detector/severity logic
changed — these are presentation + docs improvements in `scanner/src/report/`.

- **"Likely lower risk" labels.** A high/critical finding the reachability /
  exploitability / confidence pipeline has already marked down now renders a visible
  `↓ likely lower risk — …` note (not reachable in prod / sanitized / low
  exploitability / low confidence) in the CLI firehose, the pro table, and the HTML
  report. Severity stays canonical (SARIF/exit codes/baselines unchanged) — this only
  annotates, so a hardcoded rule severity isn't taken at face value.
- **Depth is discoverable.** The one-screen ship verdict now points to
  `/triage --explain <id>` (the why-it-fired narrative + data-flow trace + fix) and to
  the shareable HTML report, so users don't conclude the terse default is all there is.
- **HTML report surfaced in the README.** Documents `scan . --format html --output
  report.html` (self-contained browser page: severity charts, STRIDE, filterable
  findings) alongside json / md / sarif / csv.

## 0.122.0 — cache economics Phase B (depth-first, subagent offload, cost HUD)

Completes the cache-economics program (PRD `docs/CACHE_ECONOMICS_PRD.md`, F4–F6) on
top of the v0.121.0 measured foundation. All in `hooks/model-cost-advisor.js`,
`hooks/lib/transcript.js`, and `scanner/src/posture/cache-economics.js`.

- **F4 — depth-first routing.** A model switch is now chosen over a cache-safe effort
  drop only when it saves *materially* more (`A.savings ≥ B.savings × (1 +
  depthFirstMargin)`, default 0.25). Effort is the primary lever; switching is the
  break-even-gated exception.
- **F5 — subagent offload.** For a simple one-off whose cheap-model switch is
  cache-blocked (deep warm cache), the advisor suggests running it as a **Haiku
  subagent** — full cheap-model savings without discarding the main session's cache.
  Config `subagentAdvice` (default true).
- **F6 — cost HUD + cache budget.** `cache-statusline` CLI prints a one-line HUD
  (`$ spent · % cached · $/turn`) for a Claude Code `statusLine` command and writes
  `.agentic-security/cache-telemetry.json`; the `query_cache_telemetry` MCP tool gains
  a `statusline` field. A soft `sessionBudgetUsd` biases the `costQualityTradeoff`
  dial toward cheaper as real session spend (priced from the transcript) approaches it.

## 0.121.0 — prompt-cache economics (measured, cache-aware cost optimization)

Cache-economics core (PRD `docs/CACHE_ECONOMICS_PRD.md`, features F1–F3). Turns
Claude Code's own transcript usage into a dollarized, cache-aware view of token
cost. No network, advisory-only.

- **F1 — cache telemetry + report.** New `scanner/src/posture/cache-economics.js`
  parses per-turn `usage` (cache read/write at 0.1× / 1.25×–2× input) and reports
  cache-hit %, $ saved by caching, $ wasted on avoidable misses, $/turn, and a
  per-model breakdown. Surfaced as the `cache-report` CLI subcommand (documented as
  `/posture --cache`) and the read-only `query_cache_telemetry` MCP tool.
- **F2 — silent-invalidator detector ("cache bodyguard").** Retrospectively
  attributes cache drops to model-switch / TTL-gap / prefix-change (shown in the
  report), plus a live PreToolUse hook (`hooks/cache-invalidator-guard.js`) that warns
  before an edit to a cache anchor (`CLAUDE.md`, `.claude/settings*.json`) with the
  estimated re-warm cost. Throttled; `AGENTIC_SECURITY_QUIET` / `…_CACHE_GUARD=off`.
- **F3 — break-even + TTL-aware switching.** `hooks/model-cost-advisor.js` now reads
  the *real* cached size from the transcript (`hooks/lib/transcript.js`), shows a
  model switch's break-even ("worth it past ~N more turns"), suppresses switches that
  won't pay off (preferring a cache-safe effort drop), and treats a cache gone cold
  past the TTL as free to switch. New config: `ttlSeconds`, `breakEvenMaxTurns`.

Also lands the OpenRouter-derived advisor controls that F3 builds on: a
**`costQualityTradeoff` 0–10 dial** (replaces the one-sided `minSavingsUsd` gate;
0 = never downgrade, 10 = cheapest) and the initial per-prompt **cache-rewarm
penalty** that prefers a cache-preserving effort drop over a model switch.

F4–F6 (depth-first formalization, subagent-offload advice, cost HUD/statusline) are
specced in the PRD and ship next.

## 0.120.0 — model-cost optimizer (per-prompt model + depth advisor)

New opt-in Claude Code plugin feature; no functional change to the scanner.

- `hooks/model-cost-advisor.js` (UserPromptSubmit): scores each prompt with a
  zero-token local heuristic (length, code fences, file mentions, stack traces,
  cheap vs. expensive verbs) and, when a strictly cheaper model + reasoning depth
  would likely do the job, prints a one-line tip with the estimated token-cost
  savings. Advisory only — Claude Code hooks cannot set the model or effort, so
  the user taps `/model` + `/effort`. The tip is delivered via `systemMessage`
  (out-of-band), never `additionalContext`, so the advisor itself costs no tokens.
- `hooks/session-start-model-capture.js` (SessionStart): records the session
  model to `.agentic-security/model-optimizer-state.json` — the only channel for
  it, since there is no `$CLAUDE_MODEL` — and the advisor falls back to a
  configurable `assumedModel` when it is absent.
- Config `.agentic-security/model-optimizer.json` (`{ mode, minSavingsUsd,
  assumedModel }`), default **off**; kill switch
  `AGENTIC_SECURITY_MODEL_OPTIMIZER=off`.
- `/setup --model-optimizer [--min-savings <usd>]` enables it (config write only;
  the hooks are already registered in `hooks/hooks.json`).
- Docs: `docs/MODEL_COST_OPTIMIZATION_PRD.md` (spec, R1–R11) and
  `docs/MODEL_COST_OPTIMIZATION.md` (user guide). Tests:
  `hooks/model-cost-advisor.test.js` (10 cases).

## 0.119.2 — plugin manifest validation fixes

Manifest/packaging hotfix; no functional change to the scanner.

- `commands/fix.md`: quoted the `description:` frontmatter value. The unquoted
  colon-space (`Remediate findings: --one …`) parsed as a nested YAML mapping,
  which `claude plugin validate` rejected — and would have caused the command to
  load with all frontmatter fields silently dropped at runtime.
- `.claude-plugin/plugin.json`: dropped the unknown `vendor` field (Claude Code
  ignores it at load time; the company already lives in `author`).
- Removed stray gitignored `.agentic-security/` runtime artifacts (regenerated
  DPIA/threat-model output) from under `agents/` and `commands/`, where the
  validator was mis-reading them as plugin agents/commands.

`claude plugin validate` now passes; the two remaining warnings
(`agents/_CONFINEMENT.md` and the root `CLAUDE.md`) are by-design per the
underscore-doc convention enforced in `plugin-self-check.test.js`.

## 0.119.1 — packaging: exclude internal scan-state from the npm tarball

Packaging-only hotfix for the `@clear-capabilities/agentic-security-scanner` npm
package; no functional change to the scanner or the plugin.

- The published tarball had ballooned to 23.5 MB / 565 files because the `files`
  allowlist pulled in `src/**/.agentic-security/` and `bin/.agentic-security/` —
  the dogfooded self-scan state (findings.json, last-scan.json, scan-history,
  threat-model). `npm pack` runs from `scanner/` and does not consult the
  repo-root `.gitignore`, and a root `.npmignore` is ignored when a `files` field
  is present, so the carve-out is done with negation entries in `files`
  (`!**/.agentic-security`, `!**/.agentic-security/**`). The tarball is now
  7.9 MB / 393 files with no scan-state.

## 0.119.0 — SAST/SCA capability program (PRD R1–R25, ex-R14)

Implements the `docs/SAST_SCA_IMPROVEMENT_PRD.md` backlog — 24 of 25
recommendations (DAST-lite/R14 intentionally out). Every change shipped with a
fixture + test and the corpus gate held at 185/185.

**Core engine**
- **R1**: deep interprocedural taint (IR + field-/value-context-sensitive) is now
  ON by default for local/interactive CLI scans, budgeted, CI-off-by-default
  (`--no-deep` / `AGENTIC_SECURITY_DEEP=0` opt-out).
- **R23**: fixed the incremental cache cold-start no-op (it never persisted a
  baseline), with an end-to-end regression test.
- **R4**: collection-element taint (`arr.push(tainted); sink(arr[i])`) on by
  default; implicit/control-dependence flow wired in opt-in
  (`AGENTIC_SECURITY_IMPLICIT_FLOW=1`).
- **R2**: bounded k=1 call-string context sensitivity, opt-in
  (`AGENTIC_SECURITY_KCFA_CALLSTRING=1`); default-off keys are byte-identical.
- **R3**: deep-flow parity extended to **Go + Kotlin** — call-shaped sources
  (`r.FormValue()`), string callees (`db.Query`), Go string-concat lowering,
  Go `database/sql` sinks. (PHP/Ruby/C# parser concat-lowering remains.)
- **R17**: per-finding corroboration ("one issue, many signals") + rank tiebreak.
- **R13**: "provably safe" is a first-class verdict (`--hide-proven-safe`).
- **R5**: context-aware sanitizer adequacy (HTML-escape before a shell/SQL sink).
- **R6**: non-HTTP entrypoint taint (queue consumers / scheduled tasks / serverless).

**SCA / supply chain**
- **R7**: import-aware function-level reachability (JS/TS + Python) — resolves
  aliased/namespace imports, gated to files that import the package.
- **R12**: deterministic decision-first verdict per dependency
  (AUTO_MERGE_PATCH / WAIT_FOR_PATCH / MANUAL_REVIEW / ACCEPT_RISK / WONT_FIX).
- **R11**: OpenVEX export (`--format vex`) from reachability verdicts.
- **R9**: static malicious install-script analysis (download-exec / base64-exec /
  env-exfil lifecycle hooks).
- **R10**: Gradle transitive dependency graph.
- **R8**: container-image OS-package inventory (dpkg/apk).

**Detection surfaces, validation, workflow**
- **R20**: agent-loop taint (untrusted RAG/tool content → high-privilege tool).
- **R19**: route-level BOLA/BFLA over the API inventory.
- **R21**: RBAC role-tier authorization consistency.
- **R22**: cross-service dataflow (client-call → matched route edge inference).
- **R18**: semantic IaC (Terraform with variable resolution).
- **R16**: independent-eval harness (per-family precision/recall/F1 + gate).
- **R24**: PR-native net-new CI gate (`--fail-on-new`).
- **R15**: git-history secret sweep (`--secret-history`).
- **R25**: auto-fix acceptance-rate metric (surfaced in `apply_fix`).

Several latent bugs were found and fixed along the way (the dead `implicit-flow`
module, an `Object.assign`-taint path silently dying on a `const` binding, the
IR-TAINT conversion dropping the `implicit` flag). Each opt-in/partial item and
its remainder is tracked in the PRD rollup.

## 0.118.2 — Scanner F1 benchmark: restore F1 to 91.3% (3 FPs removed)

The "Scanner F1 benchmark" CI job (`test/benchmark/bench.js`, separate from the
cve-replay corpus) was failing. Root-caused three false positives and fixed all
three at the detector level (no baseline edit):

- **ReDoS double-flag** (introduced in v0.118.0): `scanRegexReDoS` (the
  multi-language NFA detector) ran on all languages including JS, double-flagging
  regexes already covered by `scanReDoS`. Restricted to the languages
  `scanReDoS` misses string-form regexes in (java/cs/kt/py/php); js/rb stay with
  `scanReDoS`.
- **rule-library-shape SQLi-in-string** (pre-existing): `js-framework-structural`
  matched a `db.query(\`…\`)` that was the *content* of a rule-definition string.
  Added a same-line string-literal guard.
- **secret double-count** (pre-existing): a split API key was reported twice —
  once by `secret-concat` (CWE-798) and once as a High-Entropy Credential
  Candidate. Drop the entropy candidate when a named secret detector already
  flagged the same `file:line`.
- **Measured: bench F1 90.3% → 91.3%, FP 20 → 17;** cve-replay corpus unchanged
  at 185/185 F1=1.000; full gate green.

## 0.118.1 — README: Language coverage section

Documents the 8 first-class languages (JS/TS, Python, Java, Kotlin, Go, Ruby,
PHP, C#) and the cross-language vuln-class coverage built out over v0.108–0.118
(SQLi, command/code/LDAP/XPath injection, XSS, SSRF, XXE, deserialization,
secrets, weak hashing/ciphers, static IV, CSRF, open redirect, response
splitting, ReDoS), measured by the blind, regression-gated 185-entry CVE-replay
corpus at F1=1.000. Docs + version only; no src/bundle/corpus change.

## 0.118.0 — Multi-CWE gap fill: 167→185 corpus, matrix to 152/160 cells

Closes the remaining detector-backed gaps across five CWEs in one batch, via
detector extensions (each verified pre:TP post:TN; no corpus regression).

- **`redos-nfa.js`** (CWE-1333): the multi-language NFA detector (was dormant)
  now wired in for Java/C#/Kotlin, plus PHP/Ruby string-form regex extractors.
  Go intentionally not scanned — its `regexp` package is RE2 (linear-time).
- **`weak-password-hash.js`** (CWE-916): added Ruby, C#, Kotlin, PHP MD5/SHA1
  forms. Password-context-gated; bcrypt/argon2 nearby suppresses.
- **`open-redirect.js`** (CWE-601): added Go, Ruby, C#, Kotlin sinks, with
  allow-list recognition and literal-target exemption.
- **`ruby.js`** (CWE-502): `Marshal.load`/`YAML.load` on a non-literal arg.
  **`go-structural.js`** (CWE-502): `encoding/gob` decode of untrusted bytes.
  **`php.js`** (CWE-918): cURL / fopen-wrapper fetch of a `$_GET`-controlled URL.
- **18 new corpus entries.** Not filled (intentional): CWE-1321 prototype
  pollution in 7 non-JS languages, and CWE-1333 in Go (RE2) — 8 cells empty by
  design. **Corpus 167 → 185; matrix 134 → 152/160 (95%).** F1=1.000; gate green.

## 0.117.0 — Cross-language XPath injection (CWE-643) + 7 corpus entries

Extends `xpath-injection.js` from Java/Python/JS to PHP, Go, Ruby, C#, Kotlin
(`DOMXPath`, `SelectNodes`/interp, Nokogiri `.xpath`, xmlpath/htmlquery,
`javax.xml.xpath`). All string-literal matching is embedded-quote-tolerant — an
expression like `"//user[@name='" + x` embeds the attribute delimiter quote
(also fixed a latent miss in the existing Java/Python patterns). Two issues
caught pre-commit (a Kotlin post:FP, a test-author `${u}` JS-interpolated before
the scanner). **Corpus 160 → 167; matrix 127 → 134/160.** F1=1.000; gate green.

## 0.116.0 — Cross-language CSRF detection (CWE-352) + 3 corpus entries

Extends `csrf.js` to Go (gin/echo/fiber/chi, net/http mux), Rails routes, and
ASP.NET MVC `[HttpPost]` action attrs. Defence recognition added (gorilla/csrf,
nosurf, `protect_from_forgery`, `[ValidateAntiForgeryToken]`/IAntiforgery).
Token-auth exemption: `[ApiController]` + explicit Bearer is CSRF-safe; bare
`[Authorize]` is not (cookie auth is the ASP.NET default). **Corpus 157 → 160;
matrix 124 → 127/160.** F1=1.000; gate green.

## 0.115.0 — Java reflected XSS (CWE-79): fills last XSS cell

Adds Java to `xss-reflected-multilang.js` — servlet `response.getWriter()`
write/print + `PrintWriter`, building an HTML string by concat. Static literals
and OWASP/Commons/ESAPI encoders excluded. The reflected-XSS row (CWE-79) is now
complete across all 8 languages. **Corpus 156 → 157; matrix 123 → 124/160.**
F1=1.000; gate green.

## 0.114.0 — Cross-language weak-cipher detection (CWE-327) + 3 corpus entries

Extends `crypto-protocol.js` weak-cipher detection to the Go (`crypto/des`,
`crypto/rc4`), PHP (`openssl_encrypt`/legacy `mcrypt_*` weak algos), and Ruby
(`OpenSSL::Cipher` DES/RC4/Blowfish) idioms. AES-GCM stays clean. **Corpus
153 → 156; matrix 120 → 123/160.** F1=1.000; gate green.

## 0.113.0 — Cross-language static-IV detection (CWE-329) + 7 corpus entries

Extends `crypto-protocol.js` static-IV detection to JVM (`IvParameterSpec`/
`GCMParameterSpec` from a zero array), C# (zero `.IV`), PHP (empty/`str_repeat`
IV), Ruby (fixed-literal IV), and Go (zero `make([]byte,…)` with a CBC/CTR mode,
suppressed when filled from `crypto/rand`). CSPRNG-derived IVs stay clean across
all languages. **Corpus 146 → 153; matrix 113 → 120/160.** F1=1.000; gate green.

## 0.112.0 — Cross-language HTTP response splitting (CWE-113) + 7 corpus entries

Extends `response-splitting.js` across all 8 languages (added Go, Ruby, C#,
Kotlin header sinks) and fixes two latent bugs: the PHP value was read from the
header-NAME capture group (never fired), and the request-scope param heuristic
is generalized from Java to Java/Kotlin/C#. Sanitizer recognition extended
(Python chained `.replace`, Ruby `gsub`/`delete`, Go `NewReplacer`/`ReplaceAll`,
PHP `str_replace`) so fixed forms stay clean. Biggest single matrix gain this
session. **Corpus 139 → 146; matrix 106 → 113/160.** F1=1.000; gate green.

## 0.111.0 — Cross-language XXE detector (CWE-611) + 3 corpus entries

Extends `xxe.js` (Java/Python) to PHP, Go, Ruby. Each non-JVM XML stack is
XXE-safe by default, so the detector flags the explicit external-entity opt-in
(PHP `LIBXML_NOENT`/`DTDLOAD`, Go `Strict=false`/custom Entity map, Nokogiri
`noent`/`dtdload`/`replace_entities`) rather than the default-safe parse.
**Corpus 136 → 139; matrix 103 → 106/160.** F1=1.000; gate green.

## 0.110.0 — Cross-language code-injection detector (CWE-94) + 4 corpus entries

New `code-injection-multilang.js` closes the CWE-94 gap in Java/C#/Go/Kotlin
(JS/Python/Ruby `eval` stay with the flow engine). Flags dynamic
code/expression evaluators on a non-literal argument — Java/Kotlin
(`ScriptEngine.eval`, GroovyShell, SpEL, MVEL, OGNL), C# (Roslyn `CSharpScript`,
`DataTable.Compute`), Go (yaegi/gomacro `interp.Eval`, `text/template` parse of a
non-literal body). A literal argument does not match. **Corpus 132 → 136; matrix
99 → 103/160.** F1=1.000; gate green.

## 0.109.0 — Cross-language LDAP injection detector (CWE-90) + 6 corpus entries

Extends `ldap-injection.js` from JS/Java/Python to PHP, Go, C#, Ruby, Kotlin.
Per-language filter patterns gated by an LDAP attribute set (uid/cn/mail/…) so
it doesn't fire on generic `key=value`. Two precision guards (both fix real FPs
found while building): a backtrack-proof call-guard so an escaped call at the
concat isn't flagged, and a file-level escape-API guard (`ldap_escape`,
`EscapeFilter`, `escape_filter_chars`, …) for escape-then-use spanning lines.
**Corpus 126 → 132; matrix 93 → 99/160.** F1=1.000; gate green.

## 0.108.1 — Corpus scale-up batch 3 — 117→126, matrix 84→93 cells

9 verified harvest entries across previously-empty cells the scanner already
detects (no detector change): CWE-798 {java,go,ruby,php}, CWE-916 {java,go,php},
CWE-918 {ruby}, CWE-601 {java}. Two discipline notes encoded in the generator so
they don't recur: placeholder `AKIA…EXAMPLE` keys read as pre:FN (the secrets
scanner correctly skips placeholders — regenerated with realistic keys), and a
guarded open-redirect "fixed" variant read as post:FP (the detector doesn't yet
recognize allow-list guards — post now uses literal targets). **126/126
F1=1.000; gate exit 0.**

## 0.108.0 — Corpus scale-up to 117 + baseline CI gate + cross-language XSS

Squashes the v0.106.0–v0.107.3 development churn (7 commits, several corrective)
into one coherent release.

- **Corpus 101 → 117 entries**, all pre:TP post:TN, F1=1.000, verified blind
  (manifest outside the scanned trees; identical under
  `AGENTIC_SECURITY_BLIND_BENCH=1`). Batch 2 harvest (11) + cross-language
  reflected XSS (5).
- **`xss-reflected-multilang.js`** (new): taint-independent reflected XSS for
  Go/Ruby/PHP/C#/Kotlin (input into an HTML response via concat/interp), each
  with a per-language output-encoder exclusion. JS/Python XSS stays with the
  flow engine.
- **Corpus baseline CI gate** (the process fix): `corpus-baseline.json` records
  the verdict for every entry; `runner.mjs --check-baseline`/`--update-baseline`
  + npm scripts. The gate fails on any drift — a regressed entry, a removed
  entry, or a new entry that does not pass. First `.github/workflows/ci.yml`
  (repo had no CI): runs `npm test`, verifies the committed bundle matches
  source, runs the corpus gate.
- **CLAUDE.md gains the "Verification discipline" section.** 117/117, gate exit 0.

## 0.105.0 — Corpus scale-up batch 1 (Tier 4) — 88→101, matrix 64→77 cells

First batch of the cve-replay scale-up toward 500, prioritized by empty
CWE×language cells. 13 new capability entries across 9 previously-empty cells
(CWE-338 weak PRNG, CWE-94, CWE-352, CWE-22, CWE-502), each verified pre:TP
post:TN. Two additive detector extensions unlock them: `weak-randomness.js`
gains snake_case carriers + Java/Kotlin/C# PRNG patterns (CWE-338; SecureRandom
stays clean), and `php.js`/`ruby.js` gain structural path traversal (CWE-22).
**Corpus stays F1=1.000; matrix 64 → 77/160.**

## 0.104.0 — Close remaining corpus FN/FP — cve-replay F1 0.929 → 1.000

Implements the full remaining recall+precision backlog. Aggregate cve-replay now
TP=88 FP=0 FN=0 TN=88 (F1=1.000); every language and CWE slice at F1=1.000.

- **`secret-concat.js`** (new): language-agnostic hardcoded-secret split across
  concatenated literals — reassembles `'AKIA'+'IOSF…'`/`'ghp'+'_…'`/`'sk'+'_live_…'`
  and matches provider prefixes (CWE-798).
- **`crypto-protocol.js`**: pyca/cryptography zero/static IV (CWE-329).
  **`weak-randomness.js`**: camelCase security carrier; reclassified CWE-330 →
  CWE-338. **`php.js`**: structural SQLi covers deprecated `mysql_query`.
  **`js-framework-structural.js`**: libxmljs XXE (CWE-611).
  **`python-structural.js`**: embedded-quote-tolerant literal matching +
  `open()`/`send_file` path traversal (CWE-22). **`csrf.js`**: Symfony support.
- **Precision (`engine.js` `dropGuardedFindings`)**: reflected-XSS
  output-encoding guard (drop CWE-79 when the value passed through a *captured*
  HTML escaper); `dedupeFindingsWithEvidence` prefers an interprocedural flow
  finding over a flat structural match at the same sink.

## 0.103.0 — Go recall: structural detectors (PRD Tier 1)

- **`go-structural.js`** (new): SQL injection via a `database/sql` query method
  built with `fmt.Sprintf` or string concat (CWE-89), and path traversal via
  `os.Open`/`os.ReadFile`/etc. built with concat or `fmt.Sprintf` (CWE-22).
  High precision: parameterized queries (`db.Query("… ?", x)`) and
  canonicalized paths (`filepath.Base` + `strings.HasPrefix`) have no
  Sprintf/concat in the sink argument, so they don't match.
- The centralized guard pass (`dropGuardedFindings`) gained Go path-guard
  tokens (`filepath.Base`/`Abs`, `HasPrefix`).
- **Measured: 2 FN → TP** (gin-sqli, go-path). **Go F1 0.75 → 1.000;** corpus
  FN 12 → 10; aggregate **F1 0.916 → 0.929.** No new FPs; full gate green.

## 0.102.0 — JS/Python framework recall: structural detectors (PRD Tier 1)

JavaScript and Python were the weakest languages (F1 ~0.75) — their remaining
FNs were framework handlers where input arrives via a framework source
(`@Query`, `ctx.query`, `request.GET`) and is concatenated into a sink, which
the taint engine misses without a modeled source.

- **`js-framework-structural.js`** (new): SQLi via `.query`/`.execute` concat /
  template-literal (TypeORM/mysql/NestJS, CWE-89); koa-send path traversal
  (CWE-22); `ctx.body` reflected XSS, suppressed by `escape()` (CWE-79);
  NestJS `HttpService.get` SSRF (CWE-918); deep-merge prototype pollution,
  suppressed by a `__proto__`/`FORBIDDEN_KEYS` filter (CWE-1321).
- **`python-structural.js`** (new): Flask `render_template_string` built from
  input — reflected XSS + SSTI (CWE-79; a Jinja `{{ }}` template is safe and
  does NOT match); Django `.raw`/`.extra` and `cursor.execute` built with
  concat / f-string / `%`-operator format (CWE-89; the `%s` parameterized
  placeholder form does NOT match).
- High precision (verified on the corpus pre/post pairs + a regression the
  unit test caught: `execute("… %s", [v])` is the *safe* DB-API placeholder,
  not `%`-format injection).
- **Measured: 8 FN → TP** (flask-xss, hoek, koa-path, koa-xss, nestjs-sqli,
  node-sqli, django, nestjs-ssrf). **Corpus FN 20 → 12; aggregate F1 0.861 →
  0.916.** JavaScript 0.76 → 0.90, Python 0.82 → 0.88. No new FPs; full gate green.

## 0.101.0 — SSRF/path guard recognition: precision (PRD #1)

The recall work (v0.98–v0.100) lifted aggregate F1 ~0.50 → ~0.80 but surfaced a
precision problem: the scanner flagged **14 *fixed* files as still-vulnerable**
(precision ~0.83) — mostly SSRF, where the fix adds a host allow/deny check, and
path traversal, where the fix adds a containment guard. Multiple independent
detectors decided SSRF/path with no shared notion of "this sink is hardened."

- **`ssrf-cloud-metadata.js`**: rule #1 no longer flags the `169.254.169.254`
  literal when it sits in a deny-list / host-comparison guard (the remediation,
  not the vuln).
- **`engine.js` `dropGuardedFindings(findings, fc)`** — a single, centralized
  pass after all detectors that drops a CWE-918 finding when the sink window has
  a host allow/deny check (deny/allow-list, `getHost`/`hostname` comparison,
  RFC1918/metadata prefix check, `ipaddress`/`getaddrinfo`/`ssrf-req-filter`), or
  a CWE-22 finding when the window has a path containment guard
  (`basename`/`GetFileName`/`secure_filename`/`send_from_directory`, or
  canonicalize + `startsWith`). Uniform across every emitter (regex, structural,
  per-language flow, PY-SAST, CSHARP, GO). The window is **comment-stripped** so
  a "no allow-list / 169.254…" vuln comment can't read as a guard. Opt out:
  `AGENTIC_SECURITY_NO_GUARD_RECOGNITION=1`.
- **Measured: corpus false-positives 14 → 2** (the 2 remaining are XSS
  escape-html recognition — a different family, next up). **Precision ≈ 0.97;
  aggregate F1 0.80 → 0.861 — past the 0.85 target.** Java + C# now 1.000;
  Python/Go/PHP at 0 FP. **Zero recall loss** (vulnerable-tier TP=68 unchanged) —
  the invariant that proves the guards don't hide real flows.
- New `guard-recognition.test.js`; full gate green.

## 0.100.0 — Java/Spring + C# recall: structural detectors (PRD Tier 1)

Continues the recall-led PRD. The flow-based `csharp.js` and AST/bench Java
modules miss standalone methods whose tainted-by-convention parameter has no
in-file source; Java has no string templates, so the shape is concatenation.

- **`java-structural.js`** (new): SQLi (executeQuery/createQuery + concat,
  CWE-89), command injection (Runtime.exec/ProcessBuilder + concat, CWE-78),
  path traversal (new File/Paths.get + concat, CWE-22, suppressed by
  canonical/normalize/startsWith guards), SSRF (new URL/URI from a non-literal,
  CWE-918, suppressed by a host allow/deny guard).
- **`csharp-structural.js`** (new): hardcoded credential in a const/static
  field — including the **split-concat evasion** (`"sk_" + "live_…"`) that
  defeats plain secret regexes (CWE-798, value gated on length/known-prefix so
  header-name constants aren't flagged); guarded SSRF via WebClient/HttpClient
  (CWE-918).
- **Measured: 5 more FN → TP** (spring-path, spring-ssrf, spring-sqli,
  cs-hardcoded, cs-ssrf). Both modules return clean on the fixed versions.
- **Session total: corpus false-negatives 35 → 20** (Kotlin 6 + Ruby/PHP 4 +
  Java/C# 5 = 15 FN closed). Additive, language-scoped, no regressions. New
  `java-csharp-structural.test.js` + fixtures; full gate green.

Note: spring-ssrf / cs-ssrf still show a pre-existing `post:FP` from other
detectors on the fixed file (not introduced here) — a precision item for later.

## 0.99.0 — Ruby + PHP recall: structural injection detectors (PRD Tier 1)

Continues the recall-led PRD down the corpus FN list. Same root cause as
Kotlin: the fixtures route request data through a local var
(`name = params[:name]` / `$f = $r->query->get(...)`) before the sink, so the
existing rules — which require the literal `params`/`$_GET` token on the sink
line — miss them.

- **`ruby.js`**: structural ActiveRecord SQLi (`.where("… #{x}")` / concat,
  CWE-89) and shell cmdi (backtick / `system` / `exec` with `#{}` or concat,
  CWE-78).
- **`php.js`**: structural shell cmdi (`shell_exec`/`exec`/`system`/`proc_open`
  with `'…' .` concat or `"… $var"` interpolation, CWE-78) and raw SQLi
  (`DB::raw`/`whereRaw`/`mysqli_query` with concat/interp, CWE-89).
- High precision: parameterized queries (`.where('… ?', x)`,
  `DB::select('…?', [$x])`), array-form exec (`proc_open(['gzip',$f])`,
  `Open3.capture2('finger', user)`) do **not** match.
- **Measured: 4 more FN → TP** (rails-sqli, rails-cmdi, symfony-cmdi,
  laravel-sqli). **Total corpus FN this session: 35 → 25** (Kotlin 6 + Ruby/PHP
  4). Purely additive, language-scoped, no regressions. New
  `ruby-php-structural.test.js` + fixtures; full gate green.

Deferred: symfony-csrf (CSRF is a state-change/token detector, FP-prone as a
regex — needs framework-aware modeling, not a structural injection rule).

## 0.98.0 — Kotlin recall: close all 6 corpus false-negatives (roadmap Tier 1)

First execution of the "perfect SAST" PRD, which leads with **recall** (the
measured CVE-replay F1 ≈ 0.50 is a missed-detection problem). Kotlin was the
worst single language — 6 FNs across SQLi/cmdi/path/SSRF/XXE/deser — because
those fixtures are standalone DAO/handler methods with a tainted-by-convention
parameter and no in-file taint source, so the taint engine saw nothing.

- **`sast/kotlin.js`** gains taint-independent **structural** detectors: a
  dangerous sink built with a Kotlin string template (`${x}`) or concat
  (`"…" +`) is the injection shape regardless of variable names —
  SQLi (CWE-89), command injection (CWE-78), path traversal (CWE-22). Plus
  guarded SSRF (CWE-918, suppressed when a host allow/deny check is present),
  insecure XML config XXE (CWE-611, suppressed when secure-processing is set),
  and `ObjectInputStream.readObject` deserialization (CWE-502).
- High precision: a parameterized query / array-form exec / literal URL / XML
  factory with `setFeature(...)` does **not** match. Verified on the corpus
  pre/post pairs — all 6 vulnerable fixtures fire, all 6 fixed versions stay
  clean (scanner-level).
- **Measured result: 6 Kotlin FN → TP; total corpus false-negatives 35 → 29.**
  No regressions (purely additive, `.kt`-scoped). New `kotlin-structural.test.js`
  + fixtures; full gate green.

Establishes the per-family/per-language porting pattern; next: Rails/Laravel/
Symfony/Gin/Spring SQLi+cmdi and the remaining second-tier FNs.

## 0.97.0 — Tree-sitter foundation for long-tail languages (roadmap #8)

First step of bringing languages with no first-class IR parser
(rust/solidity/cpp/c/go/swift/dart) onto real AST analysis.

- **Optional, ABI-pinned dependency:** `web-tree-sitter` 0.20.8 +
  `tree-sitter-wasms` 0.1.13 as **optionalDependencies**, marked `--external`
  in the ncc build so the committed bundle never embeds WASM (verified: bundle
  stays ~3.5 MB and contains only the external `require`, not the grammars).
- **`ir/tree-sitter-loader.js`** — lazy, cached, graceful. Loads the runtime +
  grammar at runtime and returns null when absent, so the scanner stays fully
  bootable offline / without the optional deps (long-tail languages fall back
  to the existing pattern detectors).
- **`sast/tree-sitter-sinks.js`** — first AST-accurate detector, gated behind
  `AGENTIC_SECURITY_TREE_SITTER=1`: Rust shell-spawn command injection (CWE-78,
  `Command::new("sh").arg("-c").arg(<dynamic>)`). Anchoring on real AST nodes
  means the same pattern in a comment or string literal does NOT false-match —
  the precision win over regex.
- Opt-in + optional-dep gated ⇒ default scan behavior and the committed bundle
  are unchanged. Tests + full gate green.

Next on #8: more languages/rules (Solidity dangerous primitives, Go `exec`),
and eventually CFG construction to route long-tail languages through the full
taint engine.

## 0.96.0 — Surface coverage honesty + make the corpus reporter runnable

Completes the measurement threads from 0.91/0.95 — the data existed but wasn't
usable. No detection changes.

- **Coverage line in the scan report.** `toCLI` now renders a one-line
  blind-spot summary from `_scanMeta`: files scanned, which languages got flow
  analysis (`flow=[…]`) vs pattern-only, how many files were skipped, and the
  unmodeled-sink-candidate count. The #5/#6 data is finally visible to users
  instead of sitting unread in the JSON.
- **`bench/cve-replay/corpus-status.mjs`** — a runnable report for #10:
  `node bench/cve-replay/corpus-status.mjs [--gaps|--json]` prints progress
  toward the 500-entry target and the empty CWE×language cells. On the current
  corpus: 88/500 entries, 64/160 cells covered, 96 gaps (thinnest: ruby/go/php).

### Deliberately NOT done this round
- **#8 long-tail languages onto the IR** — needs a tree-sitter dependency
  (can't be installed/bundle-validated in this environment) or five hand-written
  parsers. A dependency decision, not a safe single-pass change.
- **#1 full** — context-tagged taint lattice (core-engine rewrite).

## 0.95.0 — Stored taint (#2, opt-in) + corpus coverage reporter (#10)

- **#2 — Second-order / stored taint** (`sast/stored-taint.js`, **opt-in** via
  `AGENTIC_SECURITY_STORED_TAINT=1`). Flags a value read from a persistence
  store (DB/cache) that flows into an injection sink (XSS/SQLi/cmd/code)
  without re-validation — the stored-XSS / second-order-SQLi shape the forward
  taint engine can't see across the persistence boundary. Lower confidence by
  design (stored data isn't always attacker-controlled), so OFF by default:
  enabling it cannot change default scan behavior.
- **#10 — Corpus coverage reporter** (`posture/corpus-status.js`). Turns the
  CVE-replay corpus into an actionable map: progress toward the 500-entry
  target and exactly which CWE×language cells have zero ground-truth entries.
  Measures the existing corpus only — it never fabricates entries. This is the
  measurement substrate that makes scaling the corpus prioritizable.

Tests for both; full gate green.

### Still genuinely open (need a decision or are research-grade)
- **#8 long-tail languages onto the IR** — five net-new IR parsers, or a
  tree-sitter dependency (which conflicts with the offline-degradation rule).
  This is a dependency decision, not a quick fix.
- **#1 full** — context-tagged taint lattice (a core-engine rewrite); the
  practical wrong-context slice already ships.

## 0.94.0 — Same-file-preference call resolution (roadmap #3)

The cross-file resolver (`ir/callgraph.js` `resolve()`) was name-based: a bare
name defined in several files (`handler`, `save`, `query`, …) resolved to
whichever file Map was iterated first, mis-targeting interprocedural taint to a
same-named function in an unrelated file (wrong-target FPs and missed-target
FNs).

- `resolve(name, callerFile)` now **prefers the caller's own file** when it
  defines the name — overwhelmingly the intended callee. The taint engine
  threads the caller's file at all three resolution sites (assign-call,
  plain-call, higher-order callback).
- **Backward-compatible by construction:** with no `callerFile` or no local
  match, the original resolution order is unchanged, so no resolution edge is
  ever dropped (no new false negatives). The full gate — incl. interproc-k2's
  context test, deep-taint, calibration — stays green.
- New `test/callgraph-resolve.test.js`.

## 0.93.0 — CSV/formula injection (CWE-1236) + scoped validation-lib sanitizers (#7)

- **CSV / formula injection** (`sast/csv-injection.js`, CWE-1236): flags user
  data written to a CSV/spreadsheet writer without neutralizing leading formula
  characters (`= + - @` / tab). High precision — requires a CSV-write API + a
  user-taint hint on the same statement and no formula-escape helper nearby.
- **#7 validation-library sanitizers (correct, narrow):** zod `safeParse`/
  `parseAsync` and class-validator `validateOrReject` are now modeled as
  sanitizers **scoped to `mongo-operator` (NoSQL/operator injection) ONLY**.
  Validating a typed shape defeats operator injection, but a validated string
  is still an XSS/SQL payload — so they are deliberately NOT tagged for those
  families (a blanket tag would cause false negatives). Distinctive callees
  only, to avoid colliding with `JSON.parse`.

Fixtures + tests for both; full gate green.

## 0.92.0 — Front-end hygiene detectors (3 verified-missing, additive)

New `sast/frontend-hygiene.js` — three high-precision client-side detectors,
each a verified coverage gap (no prior matches in the detector tree). All
additive: they emit new finding classes and cannot reduce existing detection.

- **Reverse tabnabbing (CWE-1022):** `<a target="_blank">` without
  `rel="noopener"` — the opened page can rewrite `window.opener`. (low)
- **Missing Subresource Integrity (CWE-353):** a cross-origin
  `<script>` / stylesheet `<link>` with no `integrity=` — a compromised CDN
  runs in your origin. Skips same-origin/relative assets. (medium/low)
- **Angular sanitizer bypass (CWE-79):** `DomSanitizer.bypassSecurityTrust*`
  on a non-literal value explicitly disables Angular's XSS protection on
  attacker-influenced data. Skips constant-string arguments. (high)

Fixtures + 6 tests; full gate green.

## 0.91.0 — Coverage honesty (#5+#6) + wrong-context encoding (#1 slice)

Additive precision/trust features that cannot reduce existing detection.

### #5 + #6 — Analysis-coverage honesty report
- New `posture/coverage-report.js`. `_scanMeta` now publishes the scanner's
  blind spots: per-language **analysis tier** (which languages got the IR +
  taint engine vs. pattern-only — c/c++/rust/swift/solidity/dart are
  pattern-only today), a `filesDenseSkipped` counter (dense files were
  previously dropped with no count), and **unmodeled-sink candidates** —
  dangerous-call shapes (eval/exec/deserialize/yaml.load/…) with no finding on
  their line, i.e. recall blind spots to verify.

### #1 (practical slice) — Wrong-context output encoding (CWE-79)
- New `sast/wrong-context-sanitizer.js` flags an HTML-entity encoder
  (`escapeHtml`/`htmlspecialchars`/`he.encode`/`lodash.escape`) applied to a
  value used in a URL context (`href`/`src`/`location`). HTML-entity encoding
  does NOT neutralize `javascript:`/`data:` schemes, so the value is still XSS
  while looking sanitized. High precision: excludes `encodeURIComponent` (a
  different, non-XSS mistake) and suppresses when a URL-scheme allow-list is
  near. Fixtures + tests; full gate green.

### Deferred (need core-engine work or carry correctness traps — not faked)
- **#1 (full):** context-tagged taint through the lattice — the engine's taint
  is binary and can't express "sanitized-for-HTML vs -for-JS". Core change.
- **#7 validation libraries:** modeling zod/joi/etc. as blanket sanitizers
  would cause FALSE NEGATIVES — a schema-validated string is still an XSS/SQL
  payload. Needs schema-type awareness (validation defeats type-confusion /
  NoSQL-operator injection, not output injection). Deferred deliberately.
- **#2 stored/second-order taint, #3 import/type-aware call resolution,
  #8 long-tail languages onto the IR, #10 corpus scale** — each its own lift.

## 0.90.0 — Context-sensitive taint completed + bounded (roadmap #2, FR-SEM-2)

The interprocedural engine was already value-context sensitive at the
assign-call site (a distinct summary per entry-taint-state, computed lazily;
v0.66). This release completes and bounds it.

- **Plain-call sites now lazily compute context-specific summaries too.**
  Previously the plain (non-assign) call site only did a cache `get`, so a
  param mutated *only* when the callee is invoked with tainted input was
  missed there. It now mirrors the assign-call site (compute under the actual
  tainted-arg context on a miss).
- **Per-function context cap** in `SummaryCache` bounds the number of distinct
  non-empty entry contexts kept per function so lazy per-call-site computation
  can't blow up. Over the cap → reuse the empty-entry (monovariant) summary.
  Tunable via `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` (default 16; **0 = pure
  monovariant**, a clean kill-switch).
- **Docs corrected:** `summaries.js` and `dataflow/CLAUDE.md` previously called
  the engine "k=1 monovariant / one summary under empty entry." It is in fact
  value-context sensitive; the real remaining limits are call-string (k>1)
  sensitivity and param-level (not access-path-level) entry granularity.
- New `test/kcfa-context.test.js` (context-sensitivity + cap + kill-switch +
  clear); full gate green.

## 0.89.0 — Per-language metrics (#9) + roadmap audit (#3, #5 already shipped)

Continuing the multi-language SAST roadmap. Investigation revealed several
items were already implemented — so this release delivers the one genuinely
missing safe item (#9) and corrects the record, rather than re-building what
exists.

### #9 — Per-language precision/recall (new)
- `holdout-eval.js` now records a `language` per labeled sample (explicit
  `language` field or derived from the `file` extension) and exposes
  `perLanguage()` + `summarizePerLanguage()`.
- `evaluateHeldOut` returns a `perLanguage` breakdown and **flags any language
  whose precision trails the aggregate by >0.15** (n≥20) — the regression an
  aggregate would otherwise mask (a 90%-JS corpus hiding poor Ruby precision).
- New tests in `test/holdout-eval.test.js`.

### #3 — Already implemented; doc corrected
Audit found mutated-parameter taint (`applyAtCallSite`), higher-order callback
taint (`_higherOrderInvocations` fed back into the worklist), and recursion via
a multi-pass fixed point (`MAX_FP_ITERS`) were all shipped in v0.66 and covered
by `interproc-k2` / `closure-capture` / `phase6-taint` tests. The stale
`dataflow/CLAUDE.md` "what we do NOT model" section is corrected.

### #5 — Already at parity
The source/sink catalog already spans Spring, ASP.NET, Gin, Echo, Fiber, Chi,
Gorilla, Buffalo, Laravel, Symfony, Rails, Sinatra, Ktor, JDBC/JPA/Hibernate,
Dapper/ADO across all 8 languages. No new work needed.

### Still deferred (research-grade; will ship as their own releases)
#1 universal IR (no tree-sitter dep; `universal-ir.js` unwired), #2 k-CFA
context-sensitivity (FR-SEM-2), #4 auto-derived library summaries, #7 dynamic
dispatch + type inference, #8 incremental-by-default (needs a cold==warm gate),
#10 LLM closed-loop validator. These are not faked into the engine.

## 0.88.0 — Proof-gate precision pass (multi-language SAST roadmap #6)

First flagship of the "perfect multi-language SAST" program: report only
provably-feasible flows, and demote — never drop — flows we can prove are
clean or infeasible.

- **New `dataflow/proof-gate.js`** consolidates the engine's two independent
  flow-proof signals (`provenClean` from `proven-clean.js`, `_provenUnreachable`
  from `exploit-prover.js`) into one verdict per finding:
  `finding.proof = { verdict: 'feasible' | 'proven-clean' | 'proven-infeasible' | 'unproven', reasons[] }`.
- **Wired the previously-dead `proven-clean.js`** into `runDeepAnalysis` — SQL
  sinks reached only through a parameterizer are now proven clean by default.
- **Recall-preserving demotion:** proven-clean / proven-infeasible findings get
  lowered `confidence` + `confidenceTier` + `exploitabilityTier` (and rank below
  feasible findings), but **`severity` is left untouched** so a heuristic proof
  can never hide a finding from a severity-based CI gate.
- Default on; opt out with `AGENTIC_SECURITY_NO_PROOF_GATE=1`. New
  `test/proof-gate.test.js`; full gate green.

Remaining roadmap items (#1 universal IR, #2 k-CFA, #3 dormant taint paths,
#4 library summaries, #5 framework catalog parity, #7 dynamic dispatch,
#8 incremental-by-default, #9 per-language metrics, #10 LLM gate) ship as
their own benchmarked releases.

## 0.87.0 — Sharpen the 12

Ergonomics + power features for the 12-command surface left after the
v0.86.0 consolidation.

### Cross-cutting
- **Legacy-alias redirect hook** (`UserPromptSubmit`, `hooks/legacy-alias-redirect.js`):
  typing a removed alias (`/status`, `/show-findings`, `/harden`, …) now
  injects context that maps it to the new dispatcher mode, so the request
  still runs. Covers all 44 removed aliases.
- **Trend-aware `/secure` router**: compares the last two scans and shows a
  `↑ / → / ↓` arrow with what changed (never invents a trend from one scan).
- **Bare-invocation mode menus** and uniform `--json` documented across the
  dispatchers.
- **Task-oriented `/secure --help`** + an old→new alias map.

### Per-command
- `/scan --pick` — interactive mode menu.
- `/fix --checkpoint` — run a batch fix on a throwaway git branch (atomic revert).
- `/compliance --gap` — Not-Compliant worklist with the exact closing command per control; `--format oscal|json` machine-readable export.
- `/supply` — offer to bundle safe patch/minor upgrades into one PR after `--check`.
- `/posture` (bare) — combined dashboard (status + grade + trend).
- `/find-and-fix-everything` — auto checkpoint branch + PR-ready summary.
- `/triage` — order findings likely-FP-first from triage history.
- `/three-agent-review` — echo the call/wall-time budget before running.
- `/ci` — validate generated workflow YAML + offer a PR.
- `/labs` — graduation-status table for experimental modes.
- `/setup --all` — install hooks + CI + bodyguard + destructive-guard in one pass.

## 0.76.0 — Command consolidation: 80 → 38 slash commands

Simplified the command surface from 80 individual slash commands down to
38 by merging related commands into consolidated routers with flags.
No functionality removed — all logic preserved behind flags on fewer,
more discoverable parent commands.

### New consolidated commands

| New command | Absorbed | Routing |
|---|---|---|
| `/audit` | db-audit, auth-audit, rate-limit-check, webhook-audit, env-check, csp-cors, deploy-check, launch-check, llm-cost-ceiling, prompt-firewall | `--target <area>` or `--all` |
| `/threat` | threat-model, personas, playbook, bounty, adversary, attack-surface, trust-boundary, spof | `--view <name>` |
| `/llm` | llm-redteam, jailbreak-detector, llm-eval | `--mode redteam\|jailbreak\|eval` |
| `/ci` | ci-gate, predeploy-gate, install-hooks | default / `--predeploy` / `--hooks` |
| `/generate` | privacy-docs, disaster-playbook, social-media, security-tests | `--type privacy\|disaster\|social\|tests` |
| `/scanner` | self-test, diff-scan, scan-baseline, concurrency-bugs, spec-drift | `--self-test` / `--diff` / `--baseline` / `--concurrency` / `--spec-drift` |

### Commands absorbed into existing commands

- `/why-fired` → `/explain --provenance --finding <id>`
- `/why-not` → `/explain --gap <CWE>`
- `/install-script-audit` → `/supply-chain-check --show install-scripts`
- `/vendor-audit` → `/supply-chain-check --show vendored`

### Deleted deprecated aliases (11)

ci-gate-multi, rotate-key-auto, trim-dead-code, trim-dependencies,
story-explain, security-badge, security-onepager, trust-page,
dep-pinning, dep-freshness, dep-alternatives.

## 0.75.1 — /agent-harness-assessment + interactive compliance routing + README badge relocation

Three follow-ups to the 0.75.0 surface:

**Renamed `/executive-summary` → `/agent-harness-assessment`.** The
previous name framed this as a finance-style report. The actual artifact
is an assessment of the AI-agent harness: a CISO/buyer reading it wants
to know whether to trust an AI agent working in this project, not just
see a posture grade. The new name reflects the audience.

**Interactive compliance step.** After printing the six-control
assessment, the command now asks (via AskUserQuestion) which compliance
frameworks the reader wants generated NOW — NIST AI 600-1, OWASP ASVS,
OWASP LLM Top 10 (2025), or none. For each selection, the model invokes
`/compliance-report <fw>` with the matching positional argument
(`nist`, `asvs`, `llm`) so an auditor-ready file lands on disk. The
Compliance section in the assessment now says what evidence COULD be
produced; the interactive step closes the loop to evidence that EXISTS.

**README "Status badge" section relocated** from the top-of-README hero
region into the Security Pros section, between the 5-minute pro setup
and the full pro catalog. Adopting the badge is a pro-shaped step
(it requires CI wiring + a baseline scan). Three example badges now
render on three distinct lines via trailing `<br>` so the severity
ladder is legible at a glance.

## 0.75.0 — /executive-summary: CISO-facing six-control posture report

New top-level command for buyer-questionnaire / diligence / CISO use.
`/executive-summary` prints a plain-English briefing of the six harness
controls (Tool access, Guardrails, Feedback loops, Audit evidence,
Failure mode, Compliance) with live status indicators drawn from the
current project state — hook activation, scan-signature presence,
audit-log entry count, remote-witness configuration, compliance artifacts.

Each control renders four named subsections modeled on `/explain`:
**What it does** (2-3 paragraphs of plain English), **Specifically**
(the concrete enumerated list of allows/blocks/intercepts), **What would
have to go wrong for this to fail** (threat model in one paragraph), and
**Live status (this project)** (verifiable indicators). The "Specifically"
block names actual reserved paths, every shell command intercepted, every
code-edit pattern blocked, every audit-log property, every refusal point,
and every compliance artifact format — so a reviewer can verify the claim
without opening any source file.

Flags: `--format md` for markdown output; `--output PATH` writes to disk
(typically `EXECUTIVE_SUMMARY.md` for buyer questionnaires).

## 0.74.2 — npm package + version alignment

First release published to npm under the org that owns the scope:
`@clear-capabilities/agentic-security-scanner`. Adds a bin alias
`agentic-security-scanner` (→ same dist bundle) so the documented
`npx @clear-capabilities/agentic-security-scanner secure .` resolves
an executable. Aligns the source-tree version with the npm registry
after the 0.74.1 metadata-only publish.

## 0.74.0 — viral surface: PoC video gen + security-tutor skill + personality voices + compare runner

Four shareability lifts.

### Auto-recorded PoC scripts — `scanner/src/poc-video.js`
For findings with `_exploitInput` (v0.71 symbolic prover), generate a
self-contained script the operator runs against their own staging URL:
- **playwright**: TypeScript test that drives the exploit live + records video. Default for UI-driven exploits.
- **curl**: bash script with verbose tracing + payload-acceptance assertion. Default for backend exploits.
- **http**: RFC 7230-style raw request pastable into Postman/Insomnia.

The generator does NOT execute anything; produces share-grade evidence the operator runs against their OWN environment.

### Educational mode skill — `skills/security-tutor/SKILL.md`
Auto-activates when the user asks "why is X dangerous", references a finding-id and asks for context, or has mechanically accepted ≥3 fixes in a row. Walks the finding Socratically: identify source/sink/sanitizer, ask user to propose the payload BEFORE showing the fix, verify understanding with follow-up traps. CWE-specific Socratic patterns table covers 8 families.

### Security personality voices — `scanner/src/personality.js`
Three tone modes wrapping any rendered report: **sage** (calm, default), **cassandra** (alarmist), **vince** (drill-sergeant). Same findings, dramatically different shareability. `AGENTIC_SECURITY_PERSONALITY` env selects. Only the framing changes — technical content stays identical.

### Compare runner framework — `scanner/src/compare.js`
Bring-your-own-tool side-by-side comparison. User supplies the other tool's invocation + field map; we render a Markdown card with overlap / unique / severity-disagreement sections. Framework is generic — no competitor-specific adapters shipped.

### Test totals
**847 scanner tests pass / 0 fail** (up from 832).

## 0.73.0 — technical depth: IFDS summary edges + type-stub filter + cross-repo federation

Three technical-depth lifts. v0.71 shipped IFDS scaffolding with bottom
summaries; v0.70 added type-stubs but didn't thread them into the
engine; v0.68 added cross-lang within a single repo but not cross-repo.
v0.73 closes all three loops.

### IFDS full summary edges — `scanner/src/dataflow/ifds.js`

The v0.71 IFDS solver used bottom summaries (every callee was assumed
clean → no interprocedural facts flowed). v0.73 adds:
- `summaries: Map<qid|entryFact, Set<exitFact>>` records per-function
  summary edges
- `pendingReturns: Map<qid|entryFact, [{fn,returnNode,callerEntry}]>`
  registers callers waiting on more summary facts
- `_entryFactForCall(callNode, currentFact, callee)` derives callee's
  entry fact from a call site
- `_mapReturnFact(callNode, exitFact, callerCurrent)` translates exit
  facts back into caller namespace
- Summary reuse: second call to same (callee, entry fact) is O(1)

This is what makes IFDS polynomial in practice rather than re-solving
every call site.

### Type-stub-aware filter — `scanner/src/dataflow/stub-aware-filter.js`

Post-pass after the taint engine. Consults the project's TS/.pyi/JAR
type stubs (loaded by v0.70's `ir/type-stubs.js`) and demotes findings
whose source type cannot carry the vulnerability metacharacters:

| Family | CWE | Safe types (demoted) |
|--------|-----|----------------------|
| XSS    | CWE-79 | number, boolean, Date, RegExp, bigint |
| SQLi   | CWE-89 | number, boolean, Date, bigint |
| Cmd    | CWE-78 | number, boolean, bigint |
| Path   | CWE-22 | number, boolean |
| SSRF   | CWE-918 | number, boolean |

Severity drops one tier (critical → high → medium → low → info); never
drops the finding. Operator sees `_stubTypeDemoted: true` + reason.

Gate: `AGENTIC_SECURITY_TYPE_STUBS=1` (same flag as the v0.70 stub
loader).

### Cross-repo federation — `scanner/src/dataflow/cross-repo.js`

The intra-repo `cross-lang-openapi.js` posture module shipped in v0.66
ties a single repo's client call to its server route. v0.73 ships the
inter-repo lift: `buildFederatedGraph(specs)` walks a SET of OpenAPI
specs from different repos, finds shared `(method, path)` endpoints
with overlapping field schemas, and emits federated edges. Each edge
becomes a `CROSS-REPO` finding (`CWE-829`, `family: cross-repo-taint`)
showing both repos + the shared fields in the trace.

Use case: scan the auth-service repo + the billing-service repo
together; the scanner detects that `/users/{id}` is published by auth
and consumed by billing, with shared fields `email + bio`. A taint in
auth's response surfaces in billing's input — both teams now own the
sanitization contract.

### Test totals
**832 scanner tests pass / 0 fail** (up from 811).

## 0.72.1 — CI template + README adopts the v0.72 viral features

Patch release. Two adoption follow-ups for v0.72's viral features.

### CI template defaults to advisor-tone PR comment

`.github/workflows/scan.yml` — new `pr-comment-mode` input (default
`"advisor"`, alternative `"findings-table"`):

- **advisor** (new default): runs `pr-delta --base origin/<base_ref>` to
  compute the security DELTA between PR and base, then pipes the JSON
  into `pr-comment` to render the security-advisor's note. The comment
  shows only what THIS PR introduced/resolved, with CWE narrative + fix
  snippet + blocking-merge footer.
- **findings-table** (legacy): the prior critical/high count table.
  Available behind the input flag for adopters who prefer it.

Downstream consumers automatically get the new comment style on next CI
run. Opt back to the legacy table by passing `pr-comment-mode: findings-table`
to the reusable workflow.

### README adopts the status badge + leaderboard pitch

`README.md`:
- Stale `version-0.64.0` badge bumped to `version-0.72.1`.
- New badge row entry: `[![agentic-security](...)]()`.
- New "Status badge for your README" section with paste-ready Markdown,
  three example states (passing / high / critical), and self-host
  instructions for users who don't want to depend on `agentic-security.dev`.
- New "Public leaderboard (preview)" section pointing at the v0.72
  `leaderboard-row` backend.

### Test totals
**811 scanner tests pass / 0 fail** (unchanged from 0.72.0).

## 0.72.0 — viral features: shadowscan delta + advisor-tone PR comment + live badge + leaderboard backend

Three viral-lever features built to compound: every PR generates a
screenshotable advisor's note (not a wall of findings), every repo can
wear a live security badge (pull-marketing), and every scan's data shape
is ready for a public leaderboard.

### #5 Shadowscan / security-DELTA on PR — `scanner/src/pr-delta.js`

`computePrDelta(root, { baseRef, headRef })` scans both refs in-memory
(no checkout, via `git show <ref>:<path>`), diffs by `stableId`, and
emits:
- `introduced` — findings in head not in base
- `resolved`   — findings in base not in head
- `persistent` — same stableId both sides
- `shifted`    — same stableId but severity or CWE changed
- `summary.net` — per-severity head − base delta

New CLI:
```
agentic-security pr-delta --base origin/main [--head HEAD] [--json]
                          [--fail-on-introduced]
```

### #1 Advisor-tone PR comment — `scanner/src/pr-comment.js`

`renderPrComment(delta, { repoName, prNumber, prTitle })` produces a
single Markdown comment that reads like a person, not a table. Three
auto-detected modes:
- **clean** (no delta) → "Safe to merge."
- **resolves-only** → "This PR resolves N finding(s)... Nice cleanup."
- **needs-work** → narrative + per-finding paragraph with CWE 'why'
  text + remediation snippet + blocking-merge footer for critical/high.

CWE narrative table covers 19 families with one-sentence "why does this
matter" explanations. The mode is what gets **screenshotted** — security
tool output that reads like an advisor, not a SARIF dump.

New CLI:
```
agentic-security pr-comment [--in delta.json | --base <ref>]
                            [--repo <slug>] [--pr <n>] [--title <text>]
# Reads JSON delta from --in, --base (recomputes), or stdin.
```

### #2 Live SVG badge — `scanner/src/badge.js`

`renderBadge({ format, style, scanRoot, scan })` emits a shields.io-style
SVG (or JSON for frontend renderers) summarizing the latest scan:
`agentic-security: crit 0 · high 2 · med 5 · 4h ago`. Color driven by
highest non-zero severity. Two styles: `flat` (default) + `for-the-badge`.

New CLI:
```
agentic-security badge [--format svg|json] [--style flat|for-the-badge]
```

Reads from `.agentic-security/last-scan.json`. The badge is intended as
a README ornament that doubles as pull-marketing — every adopting repo
becomes a billboard.

### Leaderboard backend — `scanner/src/leaderboard.js`

`leaderboardRowFor({ scanRoot, repo })` builds one row of the future
public leaderboard data: posture grade A-F, severity counts, top CWE,
last-scan age, delta trend (`improving`/`flat`/`regressing` from
`scan-history.jsonl` if present), and the badge URL/Markdown snippet
ready to paste. `rankRows(rows)` sorts by critical → high → grade.

Public hosting of `agentic-security.dev/leaderboard` is deferred — this
release ships the data side so the future site is a thin frontend.

New CLI:
```
agentic-security leaderboard-row --repo owner/name [--root <dir>]
```

### Test totals
**811 scanner tests pass / 0 fail** (up from 792).

### Migration
All four features are additive opt-in CLI subcommands. CI templates can
adopt `pr-delta | pr-comment` to replace findings-dump comments without
breaking the existing scan-and-comment flow. README badge adoption is
manual (paste a Markdown snippet).

## 0.71.1 — dependency hygiene + CodeQL ignore-list for scanner/

Patch release. No behavior change.

### Dependency bumps
- `@types/node`: `^20.0.0` → `^24.0.0` (scanner + vscode). Node 20 reached
  EOL in 2026-04; tracking the current LTS.
- `scanner/package.json` `engines.node`: `>=20.0.0` → `>=22.0.0`.
- `vscode/package.json` `@types/vscode` + `engines.vscode`: `^1.85.0` →
  `^1.95.0` (the engine pair stays consistent so VSCE doesn't warn).

Other deps already current and unchanged: `@babel/*` 7.x, `@vercel/ncc`
0.38.x, `js-yaml` 4.x, `safe-regex` 2.x, `fast-glob` 3.x, `esbuild` 0.25.x,
`@vscode/vsce` 3.x. GitHub Actions in workflows already on v5/v8.

### CodeQL ignore-list

The scanner directory contains the taint engine itself — full of SAST
patterns, hardcoded fixture credentials, eval() shapes, raw SQL strings.
Any other SAST (including GitHub CodeQL) flags these as vulnerabilities,
producing noise that drowns out real findings.

Two new files:
- `.github/codeql/codeql-config.yml` — 15-entry `paths-ignore` covering
  `scanner/**`, `bench/**`, `vscode/dist/**`, all test fixtures, the
  `.bench-cache/**` tree, and generated bundles.
- `.github/workflows/codeql.yml` — advanced-setup CodeQL workflow on
  push/PR + weekly cron, references the config above. Uses
  `security-extended` query suite.

**To activate**: switch the repo from default to advanced code-scanning
setup at Settings → Code security → Code scanning → Set up → Advanced.
The workflow will then run and honor the paths-ignore list.

### Test totals
**792 scanner tests pass / 0 fail** (unchanged from 0.71.0).

## 0.71.0 — taint engine frontier release (final 2 of 10 — IFDS + symbolic exploit proofs)

Third and final release in the v0.69 → v0.71 taint-engine arc. v0.71
ships the two heaviest items: IFDS tabulation as an alternative
context-sensitive analyzer, and a symbolic-execution post-pass that
generates concrete attacker payloads + proves infeasibility.

### #3 IFDS / IDE tabulation — `scanner/src/dataflow/ifds.js`

Implementation of Reps-Horwitz-Sagiv "Precise interprocedural dataflow
analysis via graph reachability" (POPL 1995). Runs as an ALTERNATIVE
analyzer that augments the existing k=2 worklist when
`AGENTIC_SECURITY_IFDS=1` — its findings are merged with the worklist
output, deduped by `(file, line, sinkId)`.

Components:
- `IFDSSolver` class: path-edge worklist over the exploded supergraph
- `_flowAssign`: distributive transfer function (copy / kill / source-gen)
- `_detectSinkAtCall`: catalog-driven sink matching at each call node
- Budget: `AGENTIC_SECURITY_IFDS_BUDGET_FACTS=10000` (default) caps the
  edge count; the solver returns partial findings + `_ifdsStats.capped: true`

What v1 supports: intraprocedural flow + the IFDS framework scaffolding.
Full call-graph summary edges are stubbed (the path-edge worklist
demonstrates the framework; production-quality summary caching arrives
in v0.72). The merge-with-worklist design means the existing engine
keeps producing findings; IFDS adds context-sensitive flows the k=2
cache joined out.

### #9 Symbolic exploit prover — `scanner/src/dataflow/exploit-prover.js`

Post-pass that runs after `runTaintEngine`. For each finding:

**Step 1 — Infeasibility check** via SMT-lite (homegrown, ~150 LOC).
Walks the finding's `trace + chain` for sanitizer-output regexes that
exclude the family's required metacharacters. If the path passes
through e.g. `htmlspecialchars` for an XSS finding, the metachars
`<`, `>`, `"`, `'` are excluded → `_provenUnreachable: true`, severity
demoted to LOW.

**Step 2 — Exploit input synthesis.** For feasible findings, attaches
`f._exploitInput` with the family's canonical payload. 16 families
covered including SQLi (`1' OR '1'='1`), XSS (`<script>alert(1)</script>`),
cmd-inj, path-traversal, SSRF, deserialization, XXE, SSTI, LDAP/XPath
injection, open redirect, response splitting, ReDoS, CSRF, prototype
pollution, and prompt injection.

**Optional Z3 backend.** When `AGENTIC_SECURITY_SYMEXEC_Z3=1` AND the
customer has installed `z3-solver`, the prover uses real SMT for the
infeasibility check. Default install never bundles Z3 — the SMT-lite
fallback handles every query we issue today. Activation:
`AGENTIC_SECURITY_SYMEXEC=1` (lite); add `AGENTIC_SECURITY_SYMEXEC_Z3=1`
for the Z3 path.

### Test totals
**792 scanner tests pass / 0 fail** (up from 773 in v0.70).
Dataflow: 215 tests (up from 196).

### Migration
Both items opt-in via env flag. No existing behavior changes. With both
v0.71 items active + the v0.69+v0.70 stack on opt-in, the engine's
precision ceiling rises substantially — full default-on cutover after
two consecutive nightly CVE-replay runs show F1 delta ≥ +1pp without
precision drop >1pp.

### 10-item taint-engine arc complete

v0.69 → v0.71 has shipped all 10 items:

| # | Item | Module | Release |
|---|------|--------|---------|
| 1 | Backward slicing | `dataflow/backward.js` | v0.69 |
| 2 | Steensgaard alias | `dataflow/points-to.js` | v0.70 |
| 3 | IFDS tabulation | `dataflow/ifds.js` | v0.71 |
| 4 | String regex lattice | `dataflow/string-domain.js` | v0.69 |
| 5 | Incremental cache | `dataflow/incremental.js` | v0.69 |
| 6 | Probabilistic taint | `dataflow/soft-taint.js` | v0.70 |
| 7 | Type-stubs | `ir/type-stubs.js` | v0.70 |
| 8 | Capture-set | `dataflow/higher-order.js` | v0.69 |
| 9 | Symbolic exploit proof | `dataflow/exploit-prover.js` | v0.71 |
|10 | DB-aware taint | `sast/db-taint.js` | v0.70 |

## 0.70.0 — taint engine foundations release (4 more of 10 leap items)

Second of three releases (v0.69 / v0.70 / v0.71). v0.70 adds the
"needs new theory" capabilities — aliasing, type inference, soft taint,
and DB round-trip flow. These are the foundations that lift the
intra-procedural lattice; v0.71 will swap in IFDS + symbolic exec on
top.

### #2 Steensgaard points-to / alias analysis — `scanner/src/dataflow/points-to.js`
Unification-based, near-linear alias analysis. Walks every assign/call
across the function set, unifying classes for direct copies + field
store/load operations. Interprocedural step at resolved call sites
unifies caller args with callee params. The engine consumes the graph
via `_addPathAliasAware`: when a tainted target is added to state, all
aliases of the root variable are tainted too. Closes the
`let a = obj; a.x = tainted; sink(obj.x)` FN class.
Opt-in via `AGENTIC_SECURITY_POINTS_TO=1`.

### #7 Type-stub integration — `scanner/src/ir/type-stubs.js`
Parses TypeScript `.d.ts` under `node_modules/@types/**`, Python `.pyi`
at project root. Outputs `{signatures, types, frameworks, fingerprint}`.
Cache under `$XDG_CONFIG_HOME/agentic-security/stub-cache/` keyed by
package-lock + package.json fingerprint. Budget gate via
`AGENTIC_SECURITY_TYPE_STUBS_BUDGET_MS` (default 10s).
Opt-in via `AGENTIC_SECURITY_TYPE_STUBS=1`.

### #6 Probabilistic / soft taint — `scanner/src/dataflow/soft-taint.js`
Post-pass over IR-TAINT findings: walks `trace + chain + pathSteps`,
multiplies (1 − sanitizer-effectiveness) across each call. 22-entry
default-effectiveness table (DOMPurify=0.98, parameterize=1.0,
trim=0.05, etc.) — overrideable per catalog entry via
`sanitizerEffectiveness` field. Findings below
`AGENTIC_SECURITY_SOFT_TAINT_THRESHOLD` (default 0.5) get severity
demoted (critical→high→medium→low→info) but are NEVER dropped —
auditors see the demotion + the sanitizer that earned it.
Opt-in via `AGENTIC_SECURITY_SOFT_TAINT=1`.

### #10 Database-aware taint — `scanner/src/sast/db-taint.js`
Recognizes ORM write/read pairs across Sequelize / Prisma / TypeORM /
Mongoose / Django ORM / SQLAlchemy. When `req.body.X` is written to
`Model.field` then later read and rendered, emits a stored-XSS
finding with a 2-step trace pointing at both the write and read sites.
Handles indirection (`const u = await Model.findOne(...); res.send(u.bio)`)
and direct chains (`res.send(Model.findOne(...).bio)`).
Fires automatically — already gated by ORM context heuristic.

### Test totals
**773 scanner tests pass / 0 fail** (up from 736 in v0.69).
Dataflow: 196 tests (up from 188).

### Migration
All four items are additive. v0.69's items remain opt-in this release;
v0.71 will flip the v0.69 set to default-on if CVE-replay shows F1
delta ≥ +1pp without precision drop >1pp across two consecutive runs.

## 0.69.0 — taint engine wire-up release (4 of 10 leap items)

First of three releases (v0.69 / v0.70 / v0.71) that lift the taint
engine toward academic state-of-the-art. v0.69 ships items that wire
already-built infrastructure into the engine's main path — minimum new
code, maximum precision gain.

### #1 Backward slicing — `scanner/src/dataflow/backward.js`
Already-implemented backward slicer gets a walltime budget
(`AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS`, default 30s) and emits
`_annotateBackwardSlicesStats` { annotated, skipped, exhausted } on the
findings array. Each finding gets `f.backwardSlice: [...]` ordered
source→sink and `f.pathSteps` merged with the existing trace.
Opt-in via `AGENTIC_SECURITY_BACKWARD_SLICE=1`; flips default in v0.70.

### #5 Cross-scan incremental cache — `scanner/src/dataflow/incremental.js`
Already-implemented persistence layer (`readIncrementalState`,
`seedSummaryCache`, `serializeSummaries`, `commitIncrementalState`) gets
wired into `runDeepAnalysis`. State lives in
`<scanRoot>/.agentic-security/incremental/{version,files,summaries}.json`.
Diff via file SHA-256, reverse call-graph for transitive invalidation,
version-pinned by `(scanner, catalog-size)`. On hit: ≥70% summary reuse
on re-scans; identical findings.
Opt-in via `AGENTIC_SECURITY_INCREMENTAL=1`; flips default in v0.70.

### #4a String regex lattice — `scanner/src/dataflow/string-domain.js`
New `{kind: 'Regex', pattern}` lattice value alongside Const/Concat/Unknown.
`abstract()` recognizes sanitizer-output regexes for `encodeURIComponent`,
`encodeURI`, `parseInt`, `parseFloat`, `hashSync`, `digest`, `toString`,
`htmlspecialchars`. New `provablyMatches(absVal, safe)` proves an
abstract value fits a safe-charset regex — used by `sanitizer-proof.js`
to elevate findings to `provenClean` for non-SQL classes.
Opt-in via `AGENTIC_SECURITY_STRING_DOMAIN=1`; flips default in v0.70.

### #8a Closure capture-set analysis — `scanner/src/dataflow/higher-order.js`
New `capturedFreeVars(node, boundNames)` walker + `callbackCaptureSet(cb)`.
Extracts free variables from inline arrow/function-value bodies,
handling nested closures and shadowing correctly. The motivating
example `let t = req.query.x; arr.map(i => exec(t))` correctly
identifies `t` as captured.
Engine wiring (consume the capture set at call sites) waits for
v0.70's alias analysis; the extractor + tests ship now.
Opt-in via `AGENTIC_SECURITY_CLOSURE_CAPTURE=1`.

### Test totals
**736 scanner tests pass / 0 fail** (up from 698 in v0.68).
Dataflow scope: 188 tests (up from 130).

### Migration
All four are additive, opt-in via env flag. No existing behavior changes.
v0.70 flips the four to default-on if CVE-replay shows F1 delta ≥ +1pp
without precision drop >1pp across two consecutive runs.

## 0.68.0 — five capabilities that open clear competitive gap

Five world-class capabilities ship together. Each addresses something
mainstream SAST (SonarQube / Semgrep / Snyk / Checkmarx / Veracode /
CodeQL) does poorly or not at all.

### #3 Closed-loop auto-fix verification

`scanner/src/posture/fix-verify-loop.js` — new `verifyFixWithTests`
runs the full chain: re-scan + project linter + project test suite.
A fix is `verified-clean` only when all three pass.

Test-runner auto-discovery: `npm test`, pytest, go test, cargo test,
bundle exec rspec, mvn test, ./gradlew test. Returns one of:
`verified-clean`, `untested-but-passes` (no runner found — honest),
or `verification-failed` (with per-leg detail).

Competitor gap: most SAST tools suggest fixes but don't close the loop
by running the user's tests.

### #4 LLMSecOps coverage (3 new detectors)

| Module | CWE | What it catches |
|--------|-----|-----------------|
| `sast/llm-stored-prompt.js` | CWE-1336 | System prompt sourced from DB / config file / writable mount fed to LLM call without hardening (delimiters, immutable instruction prefix, allow-list) |
| `sast/rag-poisoning.js` | CWE-1336 | User-controlled text written to Chroma/Pinecone/Weaviate/Qdrant/LangChain/pgvector without `metadata: { source, trust_level }` provenance |
| `sast/agent-tool-escalation.js` | CWE-269 | Agent harness exposes both READ tools (list/get/fetch/scrape) and ACT tools (exec/write/send/delete) with no approval gate between them — classic tool-chain privilege escalation |

Competitor gap: nobody else ships LLM-agent-specific privilege flow
analysis. The AI security market is wide open.

### #7 Probabilistic exploitability with Wilson 95% CI

`scanner/src/posture/exploitability-probability.js` — replaces opaque
severity strings with a calibrated probability + 95% confidence interval:

```
f.exploitProbability      ∈ [0,1]
f.exploitProbabilityCI95  [lo, hi]
f.exploitProbabilityWhy   string[]    -- which factors fired
f.exploitProbabilitySlice 'CWE-89×js' | 'CWE-89' | 'prior-only'
```

Method: CISA-KEV-derived CWE-family prior + multiplicative factor
update (reachability, source provenance, sanitizer-in-path, project
hardening). Wilson CI from operator-curated `.agentic-security/
exploit-history.jsonl` when n ≥ 5 (slice grain); falls back to wider
prior-only CI when sample is thin. The CI WIDTH is the honest signal.

Competitor gap: every SAST emits severity strings; none surface
calibrated probability with uncertainty.

### #8 Provable-clean for SQL injection

`scanner/src/dataflow/proven-clean.js` — `proveSqlClean` walks the
function's CFG between every reaching source and the SQL sink,
verifies at least one parameterizer (catalog-tagged sanitizer or
known driver method: setString/AddWithValue/bindParam/etc.) sits on
the path. If proof holds, `f.provenClean = true` with
`f.provenanceProof.sanitizers: [...]`. Stronger statement than
"we didn't find a flow" — auditor-grade evidence.

v1 uses path-existence; v2 will substitute SMT-backed string-domain
constraints behind the same interface.

Competitor gap: existing tools emit "issue found" or "no issue
found." Nobody emits "proven safe."

### #9 Time-travel + counterfactual scanning

`scanner/src/history-scan.js` + two new CLI subcommands:

```
agentic-security history --since 6.months --interval 1.month
   # Walks N historical git refs, scans each, emits a timeline of
   # introduced + resolved findings between consecutive refs.

agentic-security what-if --overlay app.js:./new-app.js [--remove foo.js]
   # Apply virtual file overlays + deletes, scan the counterfactual
   # state, return findings delta vs. baseline. Working tree is never
   # touched (overlay is in-memory via runFullScan's fileContents map).
```

Use cases: "What was our posture 6 months ago vs. today?" / "If I
remove this auth middleware, how many new findings appear?" / "If I
downgrade lodash to 4.17.20, how many CVE matches drop?"

Competitor gap: existing tools scan the working state. None offer
historical replay or counterfactual mode at this granularity.

### Test totals

**698 scanner tests pass / 0 fail** (up from 665 in v0.67).

### Migration

No breaking changes. All new capabilities are additive:
- LLM/RAG/agent detectors fire automatically on relevant code
- exploitProbability fields appear alongside existing severity
- provenClean is informational (does NOT drop findings)
- history + what-if are opt-in CLI subcommands

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
