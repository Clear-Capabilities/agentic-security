# agentic-security

> **Defensive AppSec for the AI-coding era.**
> SAST + SCA + Secret scanning that runs *inside* your Claude Code session — flags vulnerabilities the moment Claude writes them, fixes them before you commit.

[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-15%2F15%20passing-success)](./scanner/test/smoke.test.js)
[![Findings](https://img.shields.io/badge/vulnerability%20rules-50%2B%20SAST%20%E2%80%A2%20300%2B%20CVEs%20%E2%80%A2%2060%2B%20secrets-orange)]()

**Author:** Ross Young, [Clear Capabilities Inc.](https://clearcapabilities.com) · **Status:** v0.1 — public release

---

## The 30-second pitch

AI codes faster than humans review. The result is a flood of plausible-looking code that ships with SQL injection, hardcoded credentials, and prototype pollution — vulnerabilities the AI didn't *intend* to introduce but didn't know how to avoid either.

Existing scanners (Semgrep, Snyk, gitleaks, npm audit) are decoupled from the loop that produced the bug. They run in CI, a day or a week later, by which point the AI has moved on to the next feature.

`agentic-security` lives **inside** the Claude Code session. The same agent that wrote the code reads the finding, applies the canonical fix, and re-runs tests — all before you've moved focus to a new file.

```bash
# Once installed:
/security-scan          # full SAST + SCA + Secret sweep
/security-fix <id>      # have Claude apply the canonical fix to one finding
/security-fix-all --severity critical    # batch-fix every critical finding
/security-baseline save # lock in current findings; future scans show only deltas
```

A `PostToolUse` hook silently scans every file Claude edits and surfaces only **new** high/critical findings — closing the AI feedback loop in seconds, not weeks.

---

## What you get

| Pillar | Coverage | Detection technique |
|---|---|---|
| **SAST** | 50+ vulnerability sinks across JS/TS, Python, PHP, Ruby, Java, Go, Laravel | AST-based taint tracking (JS/TS) with multi-hop cross-file BFS; regex fallback with safe-shape detection for non-JS |
| **SCA** | 20 manifest formats parsed (npm/yarn/pnpm/pip/poetry/Pipfile/composer/Gemfile/go.mod/Cargo/Maven/Gradle/pubspec) | OSV.dev CVE lookup with **vulnerable-call-depth filtering** — a CVE only escalates if your code actually imports the vulnerable export |
| **Secrets** | 60+ provider patterns (Stripe, AWS, GitHub PAT, Shopify, Slack, Dynatrace, JWT, PEM keys…) plus entropy-based catch-all | 4-gate FP filter (path, var-name, value heuristic, JSX-attr context); structural recognizers for UUIDs, hex digests, integrity hashes, data URIs, JWT examples |
| **Logic** | Race conditions, TOCTOU, account enumeration oracles, timing oracles, financial double-spend, missing re-auth on sensitive routes, basket/IDOR ownership, coupon reuse | Pattern + operational-context gating |
| **Threat modeling** | STRIDE category per finding (Spoofing/Tampering/Repudiation/Info Disclosure/DoS/Elevation) | Auto-tagged on every match |
| **Reachability** | Findings only escalate when the path is actually called from a route handler | Per-file call graph + reachability annotation |
| **Cipher analysis** | At-rest + in-transit; MD5/SHA1/RC4/3DES/TLS<1.2 flagged weak; AES-GCM/SHA256+/bcrypt/argon2 passed | Strength classifier with file-path heuristic |

---

## 60-second quickstart

### As a Claude Code plugin (recommended)

```
/plugin marketplace add clearcapabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

That's it. The 8 slash commands, 3 subagents, 3 hooks, and 4 skills are now live in your Claude Code session.

### As a standalone CLI (CI / pre-commit / scripting)

```bash
# Scan a directory, emit ANSI report
node scanner/dist/agentic-security.mjs scan . --format cli --verbose

# JSON for piping
node scanner/dist/agentic-security.mjs scan . --format json | jq '.findings[].vuln'

# SARIF for GitHub Advanced Security / VS Code Problems pane
node scanner/dist/agentic-security.mjs scan . --format sarif --output security.sarif

# Offline mode — skip OSV/registry network calls
node scanner/dist/agentic-security.mjs scan . --no-network
```

The CLI is a **single 1.9 MB self-contained file**. No `npm install`, no `node_modules`. Drop it on a CI runner and it runs.

---

## Real-world example: scanning OWASP Juice Shop

```text
$ /security-scan ./juice-shop

Agentic Security — 302 finding(s) across 455 file(s)        18.8s scan

  Severity      Count
  ────────────  ─────
  Critical      102
  High          118
  Medium        81
  Low           1

  By scanner kind:  SAST 196 · Logic 62 · SCA 38 · Secret 6

Top rules:
  33× C  Unsafe Reflection / RCE                  (CWE-470)
  33× H  IDOR — direct lookup w/o ownership       (CWE-639)
  26× H  SQL Injection                            (CWE-89)
  15× C  Angular DomSanitizer Bypass — XSS        (CWE-79)
  12× C  SQL Injection (template literal)         (CWE-89)
  12× C  Hardcoded Secret                         (CWE-798)
  11× M  Weak Randomness (Math.random for tokens) (CWE-330)

Hot-spot files:
  juice-shop/lib/insecurity.ts  — 11 findings (MD5/SHA1 password hashing,
                                  weak crypto, JWT decode without verify)
  juice-shop/routes/login.ts    — 19 findings (SQLi + reflection chain)
  juice-shop/routes/deluxe.ts   — 10 (race condition / financial double-spend)
  juice-shop/package.json       — 27 (Multer DoS x7, jsonwebtoken bypass,
                                  sequelize SQLi, lodash prototype pollution)

Standout findings:
  - lib/insecurity.ts:43         MD5/SHA1 Password Hashing      [critical]
  - routes/verify.ts:44          Prototype Pollution via [...]  [critical]
  - routes/b2bOrder.ts:23        VM Sandbox RCE Risk            [critical]
  - SCA: jsonwebtoken@0.4.0      CVE-2015-9235 sig bypass       [critical]
  - SCA: marsdb@0.6.11           Command Injection              [critical]
```

That's a real scan from one of our test runs — every finding ships with the file:line, CWE, STRIDE category, and a copy-pasteable canonical fix template. `/security-fix-all --severity critical` would dispatch Claude to remediate all 102 criticals in sequence.

---

## What makes this scanner different

The **rule corpus** itself isn't the differentiator — Semgrep, Snyk, and Checkmarx have larger ones. The differentiators are: (1) the false-positive engineering, (2) the AI-loop integration, and (3) honest privacy posture.

### 1. False-positive engineering that other scanners don't do

Most SAST tools have a recall problem ("we found 50 SQLi in your code!" — half of them aren't real) that destroys trust. We've shipped 8 PRDs of FP-reduction work. Concrete examples:

#### MD5/SHA1 weak crypto: context-aware, not blind

Most scanners flag *every* `crypto.createHash('md5')` as critical. In real codebases, MD5/SHA1 are routinely used for **non-security purposes** — cache keys, ETags, content fingerprints, deduplication. These outnumber security uses 10:1.

```js
// agentic-security: severity = info  (suppressed — fingerprint context)
const cacheKey = crypto.createHash('md5').update(JSON.stringify(args)).digest('hex');
const etag    = crypto.createHash('sha1').update(body).digest('hex');

// agentic-security: severity = critical  (security context detected)
const password = req.body.password;
const hash = crypto.createHash('md5').update(password).digest('hex');
if (hash === user.passwordHash) grantAccess();   // ← real bug
```

Our `_classifyHashContext` inspects ±5 lines for security signals (`password`/`passwd`/`token`/`hmac`/`verify*`/`compare*`) vs fingerprint signals (`etag`/`cacheKey`/`fingerprint`/`contentHash`/`dedup`). Other scanners report both as critical.

#### Sanitizer effectiveness: data-flow, not name-match

Other scanners credit any *call* to a function named `escape*`/`sanitize*`. We require the **return value** to actually flow into the sink:

```js
// Most scanners: "downgraded — sanitizer present"
// agentic-security: "high — sanitizer return discarded"
escapeHtml(req.query.q);
res.send(req.query.q);    // still vulnerable!

// Most scanners: "downgraded — sanitizer present"
// agentic-security: "info — sanitizer return is what reaches the sink"
const safe = escapeHtml(req.query.q);
res.send(safe);
```

A scan that downgrades the first case to info gives developers false confidence that XSS-prevention is in place when it isn't. We log a `sanitizer-return-discarded` suppression so you can see exactly why a downgrade was *not* applied.

#### Hardcoded credentials: 4-gate filter, not regex spam

A naive `password = "..."` regex floods the report with garbage from test fixtures, i18n strings, JSX placeholders, and example documentation. We apply four gates before emitting:

```
Gate 1 (path):     locales/ i18n/ translations/ storybook/ stories/
                   docs/ examples/ templates/ fixtures/ mocks/ stubs/
                   *.test.* *.spec.* *.fixture.* *.mock.* *.stories.*
Gate 2 (varname):  placeholder/label/hint/example/default/mock/sample/
                   demo/fake/dummy/prompt/tooltip/aria/title/column/field
Gate 3 (value):    < 8 chars, your-/change-me/<...>/TODO/xxx/test-key/
                   non-ASCII content with i18n-shaped variable name
Gate 4 (jsx-attr): match lives inside <input>/<TextField>/<Form.Control>/etc.
```

Each suppression carries a reason code (`path-filter`, `var-name-placeholder`, `placeholder-value`, `i18n-text`, `jsx-attr`) you can audit with `--include-suppressed`.

#### Entropy detection: structural recognizers for non-secrets

UUIDs, lockfile integrity hashes, base64 data URIs, and 3-part JWT samples all have high Shannon entropy but aren't secrets. Most scanners flag them. We have explicit recognizers:

```
NON_SECRET_RECOGNIZERS:
  uuid               → /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  hex-digest         → /^[0-9a-f]{32|40|64|128}$/  (MD5/SHA1/SHA256/SHA512 lengths)
  hex-public-key     → /^0x[0-9a-f]{40,128}$/
  integrity-hash     → /^sha(?:1|256|384|512)-[A-Za-z0-9+/=]+$/
  jwt-three-part     → /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
  doc-context        → surrounding lines contain "example|sample|e.g.|dummy"
```

#### Logic patterns: gated on operational context

A `Comment.create(...)` regex is critical in an e-commerce app (where reviews must be purchase-gated) and harmless in a blog/forum. We build a project-level index once per scan:

```
✗ ecommerce-app/Review.create(...)    → fires (Order/Cart/Purchase models present)
✓ blog/Comment.create(...)             → suppressed (no Order model in project)

✗ /change-email handler with no bcrypt.compare/verifyTotp     → fires
✓ /change-email handler with bcrypt.compare(req.body.cur, ...) → suppressed (re-auth present)

✗ coupon.update({used: true}) in /redeem handler  → fires (mutation context)
✓ <span>{coupon.amount}</span> in display          → suppressed (read-only)
```

### 2. AI-loop integration that nobody else has

| Trigger | What happens |
|---|---|
| Claude edits a file (`PostToolUse` hook) | Silent scan of that file; *new* high/critical findings injected as context for Claude's next turn |
| User runs `/security-fix <id>` | `security-fixer` subagent reads finding, adapts canonical fix to local code, runs tests |
| User runs `/security-fix-all --severity critical` | Loop the fixer over every critical finding, sequentially (parallel fixes can invalidate each other) |
| Bash hook on `git commit*` | `pre-commit-gate` blocks commits that introduce new critical findings vs. baseline. Override with `AGENTIC_SECURITY_BYPASS=1` |
| `/security-threat-model` | STRIDE coverage table from the last scan — surfaces under-covered categories |
| `sca-malware-analyst` subagent | Per-component CLEAN/SUSPICIOUS/MALICIOUS verdict on third-party deps with strict grounding rules |

A typical agent-driven flow:

```
You:    Add a /search endpoint that lets users query products by name.

Claude: (writes code, including a vulnerable `db.query('... WHERE name=' + req.body.q)`)
Hook:   ⚠ agentic-security: 1 new high/critical finding from this edit:
        [HIGH] CWE-89 SQL Injection (routes/products.js:42)
        → Run /security-fix-all --severity high to remediate.

Claude: I just introduced a SQL injection. Let me fix it.
        (rewrites to use parameterized query)
        (re-runs the scan — finding gone)

You:    /security-baseline save

(future commits will be blocked if anything *new* and critical lands)
```

### 3. Honest privacy posture

| | Agentic-security | Snyk | Semgrep CE | Checkmarx |
|---|---|---|---|---|
| Source code uploaded to vendor cloud | **Never** | Yes (paid) | Optional (CE: no, Pro: yes) | Yes |
| Network calls send | `purl` strings only (package@version) | Source + manifest | Source (Pro) | Source |
| Offline mode | `--no-network` flag; SCA falls back to cache | Limited | Yes | Limited |
| LLM analysis | Off by default; opt-in `sca-malware-analyst` uses your existing Claude API key | N/A | N/A | N/A |
| Telemetry | None | Anonymous metrics | Anonymous metrics | Telemetry |

---

## How we compare to other scanners

| | agentic-security | Semgrep CE | Snyk Free | gitleaks | npm audit | Checkmarx |
|---|---|---|---|---|---|---|
| **SAST** | ✅ 50+ rules | ✅ 2000+ rules | ✅ paid | ❌ | ❌ | ✅ enterprise |
| **SCA (CVE)** | ✅ OSV-backed, 20 manifests | ❌ | ✅ excellent | ❌ | ✅ npm only | ✅ |
| **Secrets** | ✅ 60+ patterns + entropy | ❌ (use Semgrep secrets, paid) | ✅ paid | ✅ named patterns | ❌ | ✅ |
| **Vulnerable-call-depth filter** | ✅ | ❌ | ❌ | n/a | ❌ | partial |
| **Sanitizer data-flow check** | ✅ | partial | ❌ | n/a | n/a | ✅ |
| **MD5 context awareness** | ✅ | ❌ | ❌ | n/a | n/a | partial |
| **AI-agent integration** | ✅ Claude Code native | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Auto-fix** | ✅ via subagent | ❌ | partial (paid) | ❌ | partial | ❌ |
| **Source code stays local** | ✅ always | ✅ CE | ❌ paid | ✅ | ✅ | ❌ |
| **Cost** | Free (ELv2) | Free (CE) | Free tier limited | Free | Free | $$$$ |
| **Single-binary distribution** | ✅ 1.9 MB | ❌ | ❌ | ✅ | ❌ | ❌ |

---

## The three pillars in detail

### SAST: AST-first taint tracking

Pure regex scanners produce noise on multi-line patterns and modern JS features (template literals, optional chaining, async/await). We use `@babel/core` to build a real AST and walk it with a custom visitor:

```js
// What our AST visitor catches that regex scanners miss:

// 1. Destructured request params
async (req: Request) => {
  const { body } = req;       // ← `body` is now tainted
  db.query(`SELECT ... WHERE id = ${body.id}`);  // ← SQLi caught
};

// 2. Re-aliased through helper functions across files
// routes/login.ts
import { lookup } from '../lib/db';
app.post('/login', async (req, res) => {
  const result = await lookup(req.body.email);   // taint flows through import
  res.json(result);
});

// lib/db.ts
export async function lookup(input) {
  return db.query(`SELECT * FROM users WHERE email = '${input}'`);  // SQLi
}
// → Cross-file BFS up to 3 hops; finding emitted on routes/login.ts:42

// 3. Reachability annotation
// findings on dead code (functions never called from a route) are
// downgraded to medium so triage isn't drowned in unreachable findings
```

Non-JS files use a regex-fallback scanner that *also* requires a tainted source in the sink's argument span — pure literal calls are not flagged:

```python
# agentic-security: 0 findings  — literal-only sinks ignored
cursor.execute("SELECT * FROM products WHERE active = 1")
print("Hello world")

# agentic-security: SQL Injection [high]
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# agentic-security: 0 findings — parameterized form recognized
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### SCA: vulnerable-call-depth filtering

Most SCA tools treat every CVE in your dependency tree as equally relevant. In practice, you only care about CVEs in functions you actually call.

```
package.json:
  lodash: ^4.17.4

CVE-2019-10744: Prototype Pollution in lodash._defaultsDeep
CVE-2021-23337: Command Injection in lodash._template

agentic-security analyzes your code:
  - Found: const _ = require('lodash')
  - Found: _.merge(...)        ← uses one vulnerable export
  - Not found: _.template(...) ← second CVE not actually exploited

Output:
  [high]   CVE-2019-10744  prototype pollution in lodash (you call _.merge)
  [info]   CVE-2021-23337  command injection in _.template (you don't call it)
```

The `markUsedVulnFunctions` engine walks every project file looking for the specific exports each CVE flags. Unused vulnerable exports get downgraded — so your high-priority queue only has CVEs you can actually reach.

### Secrets: layered detection

Three independent detection strategies, each with their own FP filters:

1. **60+ named provider patterns** — Stripe, AWS, GitHub PAT, Shopify, Slack, Dynatrace, JWT, PEM keys, etc. Patterns include checksum/length validation where the provider supports it.
2. **Entropy-based catch-all** — Shannon entropy ≥ 4.5 over a 24-120 char alphanumeric run, with the credential context check (var name contains `key`/`secret`/`token`/`password`/`auth`/`cred`/`bearer`/`signature`).
3. **Hardcoded-credential heuristic** — `password = "..."` style assignments, gated by the 4-gate FP filter.

All output is **always masked by default**:

```
[critical] CWE-798  routes/payments.ts:47  Stripe Secret Key
            value: sk_liv••••••ABCD
            fix:   Remove the hardcoded credential. Store secrets in
                   environment variables or a secrets manager. Rotate
                   the exposed credential immediately.
```

The raw value is never written to disk or printed unless `--unmask` is explicitly passed.

---

## Integration patterns

### Pre-commit gate

```bash
# .git/hooks/pre-commit
#!/bin/sh
node /path/to/agentic-security/scanner/dist/agentic-security.mjs \
  baseline diff "$(git rev-parse --show-toplevel)"
exit $?
```

Returns exit code `3` if any new critical finding lands → commit aborted.

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  agentic-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: |
          curl -L -o agentic-security.mjs \
            https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs
          chmod +x agentic-security.mjs
      - run: node agentic-security.mjs scan . --format sarif --output security.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: security.sarif }
```

Findings appear in the GitHub Security tab.

### Inside Claude Code (intended path)

The `PostToolUse` hook surfaces new findings automatically — no setup beyond `/plugin install`. Optional: enable the `PreToolUse` git-commit gate via the plugin's hook config.

### As a library (Node)

```js
import { runScan } from './scanner/src/runScan.js';
import { normalizeFindings, toSARIF } from './scanner/src/report/index.js';

const { scan, meta } = await runScan('./src');
const findings = normalizeFindings(scan);

const critical = findings.filter(f => f.severity === 'critical');
console.log(`${critical.length} critical findings`);
```

---

## Configuration

### Per-repo (`.agentic-security/config.json`)

```json
{
  "network": { "osv": true, "claudeMalwareAnalyst": false },
  "thresholds": { "blockCommitAt": "critical" },
  "ignore": [".min.js", "vendor/**", "third_party/**"],
  "ruleOverrides": { "Reflected XSS": "info" },
  "fileSizeLimitBytes": 500000,
  "maxLineAvgChars": 400
}
```

### Global (`~/.claude/agentic-security/config.json`)

Same schema; per-repo settings override global.

### CLI flags

```
--only sast|sca|secrets       Limit scan to one pillar
--format cli|json|md|sarif    Output format
--no-network                  Skip OSV/registry calls (offline mode)
--include-suppressed          Show what was filtered + reasons (FP audit)
--verbose                     Include full fix-template bodies in CLI output
--output <file>               Write report to file instead of stdout
--unmask                      (Secret scan only) print raw values — use carefully
```

---

## Exit codes

The CLI uses exit codes so you can chain it with `&&` / `||`:

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Low / Medium findings |
| `2` | High findings |
| `3` | Critical findings |
| `4` | Execution error |

```bash
# CI: fail the build only on critical findings
node agentic-security.mjs scan . || [ $? -lt 3 ]
```

---

## Architecture (one paragraph)

The scanner is a Node port of `attacksurface.html` — a 4,150-line in-browser analyzer with 50+ vulnerability sinks, 60+ secret patterns, 20 manifest parsers, OSV-backed CVE lookup, AST-based taint tracking, and STRIDE/CWE classification. The Node port replaces browser deps (`sessionStorage` → disk cache, `JSZip` → `fast-glob`) and ships as a single 1.9 MB ESM bundle via `@vercel/ncc` — zero runtime dependencies on the install target.

Plugin layout:

```
agentic-security/
├── .claude-plugin/
│   ├── plugin.json           # Plugin manifest (Claude Code reads this)
│   └── marketplace.json      # Marketplace listing
├── commands/                 # 8 slash commands
│   ├── security-scan.md
│   ├── security-sca.md
│   ├── security-secrets.md
│   ├── security-fix.md
│   ├── security-fix-all.md
│   ├── security-threat-model.md
│   ├── security-report.md
│   └── security-baseline.md
├── hooks/                    # Lifecycle hooks
│   ├── hooks.json
│   ├── post-edit-scan.js     # PostToolUse: silent scan + new-finding surface
│   ├── pre-commit-gate.js    # PreToolUse: block commits with new criticals
│   └── session-start.js      # Tip if no baseline exists
├── agents/                   # 3 subagents
│   ├── security-fixer.md     # Apply fix templates to one finding
│   ├── security-triager.md   # Score + dedupe + rank
│   └── sca-malware-analyst.md  # CLEAN/SUSPICIOUS/MALICIOUS verdict per dep
├── skills/                   # 4 SKILL.md files for Claude
│   ├── sast-scan/
│   ├── sca-scan/
│   ├── secret-scan/
│   └── fix-vulnerability/
└── scanner/
    ├── src/                  # Engine source (for development)
    ├── dist/agentic-security.mjs  # 1.9 MB self-contained CLI bundle
    ├── bin/agentic-security.js    # Source entry point (used by build)
    └── test/                 # 15 smoke tests + fixtures
```

---

## Performance

| Workload | Result |
|---|---|
| 1 file, 50 lines (vulnerable-js fixture) | 45 findings in **~250 ms** |
| 455 files, mixed JS/TS/JSON (juice-shop) | 302 findings in **18.8 s** |
| 100k LOC monorepo (target) | < 60 s end-to-end |
| Memory ceiling | < 512 MB on a 100k LOC project |
| Bundle size | **1.9 MB** (gzipped: ~600 KB) |
| Cold start | < 200 ms (Node 20, M-series Mac) |
| OSV cache hit | Cached 7 days at `~/.claude/agentic-security/osv-cache/` |

---

## Troubleshooting / FAQ

**Q: I get `Cannot find package 'fast-glob'` when I install the plugin.**
A: You're on an old version. Update: `/plugin marketplace update clearcapabilities && /plugin install agentic-security@clearcapabilities`. Since v0.1.1 the scanner ships as a single self-contained bundle.

**Q: The scan hangs on a large monorepo.**
A: Pass `--no-network` to skip OSV calls (often the bottleneck). Or scan a subdirectory: `/security-scan ./services/api`.

**Q: I'm getting too many findings on legacy code.**
A: Save a baseline: `/security-baseline save`. Future runs (and the pre-commit gate) only show *new* findings. Triage incrementally.

**Q: How do I tell which findings were suppressed and why?**
A: `node agentic-security.mjs scan . --format json --include-suppressed | jq '.suppressed'`. Each suppression has a `reason` code (`path-filter`, `entropy-jwt-three-part`, `severity-fn:non-security-context`, `logic-gate:no-ecommerce-context`, etc.).

**Q: Can I use this on Python / Java / Go code?**
A: Yes — the regex-fallback scanner covers Python, PHP, Ruby, Java, Go, Laravel. The AST taint tracker is currently JS/TS only; we'd love AST coverage for Python on the roadmap.

**Q: Will this send my code to a server?**
A: No. SAST and Secret scanning run fully offline. SCA queries OSV.dev with **package name + version only** (a `purl`) — never source. The `sca-malware-analyst` subagent (off by default) uses your existing Claude API key to send package metadata only.

**Q: What CWEs does this cover?**
A: A representative subset: 22 (Path Traversal), 78 (Command Injection), 79 (XSS), 89 (SQL Injection), 94 (Code Injection), 113 (Header Injection), 200 (Information Disclosure), 204 (Differentiated Error), 208 (Timing Oracle), 209 (Stack Trace Exposure), 307 (Missing Rate Limit), 321 (Hardcoded Key), 327 (Crypto), 330 (Weak Randomness), 338 (Weak PRNG), 347 (JWT Forge), 362 (Race Condition), 367 (TOCTOU), 434 (File Upload), 489 (Debug Route), 502 (Deserialization), 601 (Open Redirect), 611 (XXE), 614 (Cookie Flag), 620 (Re-Auth), 639 (IDOR), 798 (Hardcoded Cred), 840 (Business Logic), 862/863 (Authz), 915 (Mass Assignment), 916 (Weak Hash), 918 (SSRF), 942 (CORS), 943 (NoSQL Injection), 1004 (httpOnly), 1321 (Prototype Pollution), 1333 (ReDoS), 1336 (SSTI).

---

## Roadmap

- AST-based taint analysis for **Python** (currently JS/TS only)
- **GitHub App** that auto-comments on PRs with new findings
- **VS Code extension** that surfaces findings in the Problems pane via the SARIF output
- **Custom rule packs** loaded from `.agentic-security/rules/`
- **Real-time mode** — incremental scan as you type (currently per-`Edit` only)
- **Compliance reports** — SOC 2 / ISO 27001 / PCI DSS coverage matrices

PRs welcome; see [CONTRIBUTING.md](./CONTRIBUTING.md) (forthcoming).

---

## License

[Elastic License 2.0](./LICENSE). You may use, copy, modify, and redistribute the software for free — including inside commercial products and internal tooling. You may **not**:

- Offer the software (or substantially the same functionality) as a hosted or managed service to third parties.
- Move, change, disable, or circumvent any license-key functionality.
- Remove, alter, or obscure copyright / license notices.

For a different licensing arrangement (e.g. a SaaS exemption), contact ross@clearcapabilities.com.

---

## Author

Ross Young  ·  [Clear Capabilities Inc.](https://clearcapabilities.com)  ·  ross@clearcapabilities.com

The vulnerability detection patterns and remediation templates are derived from the `attacksurface.html` analyzer authored by Ross Young.

---

<sub>Built for the Claude Code era. The same agent that writes your code should be the one that secures it.</sub>
