# scanner/src/sast/

SAST detector modules. Each file exports one or more `scan*()` functions returning `Finding[]`. The orchestrator in `../engine.js` calls them.

## Adding a new SAST rule

1. **Pick the right module.** If your rule is language-specific (Python sink-side, Kotlin force-unwrap), it goes in or next to the existing language module. If it's framework-specific (Express auth, FastAPI hardening), use a `*-hardening.js`. If it's a cross-cutting class (CSRF, prototype pollution, mass assignment), add a new top-level `<topic>.js`.
2. **Export `scan*()`** returning `Finding[]`. Required finding fields: `id` (stable), `severity`, `file`, `line`, `vuln`, `cwe`, `description`, `remediation`. Set `family` and `parser` if you can — defaults in `../posture/finding-defaults.js` will backfill, but a detector-set value is more accurate.
3. **Import and call** in `../engine.js`. Find the existing `import { scanX } from './sast/x.js'` block and add yours alphabetically. Call the function inside `runFullScan` so its results flow into `finalFindings`.
4. **Fixture pair.** Under `../../test/fixtures/<rule-name>/` create `vulnerable/` and `clean/`. The vulnerable shape must trigger the rule; the clean shape must not.
5. **Cover it in tests.** Add to or create a `../../test/<rule-name>.test.js`. Wire it into `npm run test:sast` (or whichever scope it fits) in `../../package.json`.
6. **Build + smoke.** `npm run build` then `npm run smoke`. The lifecycle guard (`npm run test:lifecycle`) catches a rule that ships without an import in `engine.js`.

## What lives here, by category

**Language-specific** — `cpp.js`, `csharp.js`, `dart-flutter.js`, `go-extended.js`, `java-deserialization.js`, `kotlin.js`, `php.js`, `python-sinks.js`, `ruby.js`, `rust.js`, `solidity.js`, `swift.js`, `xxe.js`.

**Tree-sitter (long-tail languages, opt-in)** — `tree-sitter-sinks.js` (roadmap #8). AST-accurate detectors for languages with no first-class IR parser (rust/solidity/cpp/go/swift/dart), via `../ir/tree-sitter-loader.js`. Gated behind `AGENTIC_SECURITY_TREE_SITTER=1` and the **optional** `web-tree-sitter` + `tree-sitter-wasms` deps (ABI-pinned 0.20.8 ↔ 0.1.13, marked `--external` so they're never bundled). Degrades to a no-op when the flag or deps are absent. First rule: Rust shell-spawn command injection (CWE-78). Anchoring on real AST nodes means comments/strings can't false-match.

**Framework hardening** — `django-hardening.js`, `fastapi-hardening.js`, `laravel-hardening.js`, `quarkus-hardening.js`, `springboot-hardening.js`. Each detects "you used framework X but forgot the security-hardening step that ships with it" rather than a primary vuln.

**Cross-cutting vuln classes** — `authz.js`, `csrf.js`, `csv-injection.js` (formula injection into spreadsheet cells, CWE-1236), `host-header.js`, `jndi.js`, `jwt-exp.js`, `ldap-injection.js`, `xpath-injection.js`, `mass-assignment.js`, `mutation-xss.js`, `nosql-injection.js`, `prototype-pollution.js`, `ssrf-cloud-metadata.js`, `stored-taint.js` (second-order / stored injection — **opt-in** via `AGENTIC_SECURITY_STORED_TAINT=1`), `toctou.js`, `wrong-context-sanitizer.js` (HTML-entity encoder used in a URL context — wrong-context output encoding, CWE-79), `zip-slip.js`.

**Cloud/infra** — `db-rls.js` (Supabase RLS), `env-hygiene.js` (NEXT_PUBLIC_ leaks, .env.example real values), `mobile-manifest.js`, `pipeline.js` (CI/CD integrity), `rate-limit.js`, `webhook.js`.

**LLM / agent** — `llm.js`, `llm-owasp.js`, `llm-trading-agent.js`, `mcp-audit.js`, `model-load.js`, `prompt-firewall.js`, `prompt-template.js`.

**Agent-of-agent / Claude Code hardening** — `claude-hook-injection.js`, `claude-md-prompt-injection.js`, `claude-settings.js`.

**Auth / web** — `auth-provider.js`, `client-side.js`, `frontend-hygiene.js` (reverse tabnabbing CWE-1022, missing Subresource Integrity CWE-353, Angular `bypassSecurityTrust*` sanitizer-bypass CWE-79).

**Bench-shape adapters (label-leakage, OFF by default)** — `bench-shape/` directory, plus `cpp-bench-extras.js`, `java-bench-extras.js`, `juliet-shape.js`, `primary-cwe-java.js`. These read Juliet / OWASP-Benchmark answer keys. Disabled unless `AGENTIC_SECURITY_BENCH_SHAPE=1`; `AGENTIC_SECURITY_BLIND_BENCH=1` overrides to force everything off. **Never use their emissions as a quality signal.**

**Helpers** — `_comment-strip.js` strips comments while preserving line numbers (so finding `line` stays accurate). `index.js` is the public re-export.

## Gotchas

- **Comments confuse detectors.** Always go through `blankComments()` from `_comment-strip.js` before scanning a file body.
- **Detector snippet attribution.** Don't grab `lines[matchLine - 1]` blindly — for multi-line patterns (`exec('ping' + req.body.host, …)`), the match index and the readable sink line can diverge. Premortem item — fixed in the dataflow engine; if you're regressing on it, your fix probably needs to use the actual sink expression, not the regex's match offset.
- **Severity floor.** No detector should emit `severity: 'critical'` without strong evidence; the calibrator amplifies critical-rated findings and a flood drowns real ones. If in doubt, emit `high` and let `annotateExploitability` push it up.
- **Family field for calibration.** If you can't tell what family your rule belongs to, that's a signal the rule covers too much. Split it.
