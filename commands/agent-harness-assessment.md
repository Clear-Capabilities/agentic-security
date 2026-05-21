---
description: Agent harness assessment — six-control trust report: tool access, guardrails, feedback, audit, failure mode, compliance.
argument-hint: "[--output PATH] [--format text|md]"
---

Print a detailed plain-English assessment of the AI-agent harness in this
project. Audience: a CISO, security buyer, or diligence reviewer who has
fifteen minutes, no familiarity with this codebase, and needs to know
whether to trust an AI agent working in it.

No CWE numbers. No CVSS. Six numbered sections. Each section has four named
subsections (modeled on `/explain`):

  • What it does — the control, in plain English
  • Specifically — the concrete list of allows/blocks/intercepts
  • What would have to go wrong — the threat model in one paragraph
  • Live status (this project) — verifiable indicators from current state

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');

// ---- argument parsing -------------------------------------------------------
const args = process.argv.slice(1);
let outPath = null;
let format = 'text';
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--output' && args[i+1]) { outPath = args[++i]; format = 'md'; }
  else if (args[i] === '--format' && args[i+1]) { format = args[++i]; }
}

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));

function safeRead(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }
function safeJSON(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }
function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }
function mtimeOf(p) { try { return fs.statSync(p).mtime; } catch { return null; } }
function lineCount(p) { try { return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).length; } catch { return 0; } }

// ============================================================================
// 1. Tool access
// ============================================================================
function checkToolAccess() {
  const teamSettings = safeJSON(path.join(cwd, '.claude', 'settings.json'));
  const userSettings = safeJSON(path.join(cwd, '.claude', 'settings.local.json'));
  const denies = []
    .concat(teamSettings?.permissions?.deny || [])
    .concat(userSettings?.permissions?.deny || []);
  const confinement = exists(path.join(pluginRoot, 'agents', '_CONFINEMENT.md'));
  const mcpKill = process.env.AGENTIC_SECURITY_MCP_DISABLED === '1';
  return {
    active: denies.length > 0 || confinement ? 'on' : 'off',
    what: [
      'The agent is restricted in two directions at once. On the READ side, a per-project deny-list excludes generated bundles, cached benchmark output, the scanner\\'s own state files, and dependency directories — so a prompt injection cannot use the agent to exfiltrate cached credentials, build outputs, or third-party code it has no business reading.',
      'On the WRITE side, the harness exposes exactly one tool that can persist changes (apply_fix on the MCP server). Every other ostensibly-write-capable tool flows through this same gate. The gate refuses any path on a reserved list, any path that resolves outside the project root (even via symlink), and any patch whose corresponding scan signature does not verify against this machine\\'s private key.',
    ],
    blocks: [
      'Reserved write paths the agent can NEVER modify — even if a prompt injection asks:',
      '   • Source control:  .git/  .github/  .gitlab/  .circleci/  .buildkite/',
      '   • Dependency manifests:  package.json  package-lock.json  yarn.lock  pnpm-lock.yaml',
      '                            pyproject.toml  Pipfile  poetry.lock  requirements.txt',
      '                            go.mod  go.sum  Cargo.toml  Cargo.lock',
      '                            composer.json  Gemfile  pom.xml  build.gradle',
      '   • Container & infra:  Dockerfile  docker-compose.yml  Jenkinsfile  *.tf  *.tfvars',
      '                          k8s/  kubernetes/  .terraform/  .aws/',
      '   • Build output:  dist/  build/  target/  *.bak  *.lock',
      '   • The agent\\'s own state:  .agentic-security/  node_modules/',
      'Path-escape attempts that are rejected before any filesystem call:',
      '   • Lexical traversal (..) anywhere in the path',
      '   • Symlink-out-of-tree (refused by lstat + realpath check, not just lstat)',
      '   • Absolute paths outside the session root',
      'Tools the agent has access to are explicit and inventoried — every MCP tool call is named in the audit log (control #4).',
    ],
    bypass: 'For a successful unauthorized write to happen, an attacker would need to (a) get a subagent to hold Edit permission, AND (b) bypass the lexical + realpath path-confinement check on the target, AND (c) produce a forged HMAC signature for a fake last-scan.json using the per-install random key stored at \$XDG_CONFIG_HOME/agentic-security/scan-key (mode 0600). All three are required — the path check and the signature check happen on separate code paths. A compromise of one does not enable the others.',
    extra: [
      'Read deny rules in effect: ' + denies.length,
      'Subagent write-confinement contract: ' + (confinement ? 'present' : 'MISSING'),
      'MCP server kill switch: ' + (mcpKill ? 'ACTIVATED (AGENTIC_SECURITY_MCP_DISABLED=1)' : 'available (set AGENTIC_SECURITY_MCP_DISABLED=1 to refuse every tool call)'),
    ],
    evidence: '.claude/settings.json  +  agents/_CONFINEMENT.md  +  scanner/src/mcp/tools.js (_confine, RESERVED_WRITE_*)',
  };
}

// ============================================================================
// 2. Guardrails
// ============================================================================
function checkGuardrails() {
  const hooks = safeJSON(path.join(pluginRoot, 'hooks', 'hooks.json')) || {};
  const hooked = ['PreToolUse', 'PostToolUse', 'SessionStart', 'Stop'].filter(k => hooks.hooks && hooks.hooks[k]);
  const bodyguardCfg = safeJSON(path.join(cwd, '.agentic-security', 'bodyguard.json')) || { mode: 'warn' };
  const destructCfg = safeJSON(path.join(cwd, '.agentic-security', 'destructive-guard.json')) || { mode: 'block' };
  const active = hooked.length === 4;
  return {
    active: active ? (bodyguardCfg.mode === 'block' && destructCfg.mode !== 'off' ? 'on' : 'warn') : 'off',
    what: [
      'Two guards run BEFORE the agent\\'s action reaches the operating system. The shell guard inspects every Bash command and refuses the dangerous ones with a one-line explanation of why and what to do instead. The code-edit guard inspects every file the agent is about to write, scans for high-precision insecure patterns, and refuses the write at the source — before the file lands on disk.',
      'Both guards run as Claude Code PreToolUse hooks, so they fire on every single tool call — not just the ones the agent decides to flag. They are configurable per-project (mode = block / warn / off) and accept user-defined extra patterns.',
    ],
    blocks: [
      'Shell commands intercepted (pre-bash-guard.js — exits non-zero in block mode):',
      '   • rm -rf on a parent / home / root directory  (\"rm -rf ~\", \"rm -rf /tmp\", \"rm -rf ..\")',
      '   • rm -rf with no specific target',
      '   • DROP TABLE  /  DROP DATABASE  /  TRUNCATE TABLE  (no rollback in most DBs)',
      '   • supabase db reset  (wipes all data + reseeds; production-pointing config = production wipe)',
      '   • git push --force / -f / --force-with-lease  to shared branches',
      '   • git push --force to main / master / production / prod  (rewrites canonical history)',
      '   • git reset --hard  (discards local changes, no undo)',
      '   • git clean -fdx  (removes ignored files including .env)',
      '   • curl … | sh   /   wget … | bash   (remote-controlled shell execution)',
      '   • chmod 777  (world-writable on shared hosts is exploited)',
      '   • aws s3 rm --recursive  (irreversible without versioning, which most users do not enable)',
      '   • docker system prune -a  (removes all unused images, networks, volumes)',
      '   • vercel --prod  without preview deploy first',
      'Code-edit patterns intercepted (pre-edit-bodyguard.js — exits non-zero in block mode):',
      '   • SQL injection via template-literal or +concat on user input',
      '   • Shell command injection via exec/spawn/os.system/subprocess with user-controlled strings',
      '   • Secrets prefixed NEXT_PUBLIC_* with names like SECRET/KEY/TOKEN/PASSWORD/API_KEY',
      '   • Hardcoded credential signatures:  sk-…   ghp_…   xoxb-…   AKIA…   AIza…   pk_live_…',
      '   • dangerouslySetInnerHTML without DOMPurify / sanitize',
      '   • eval / new Function / setTimeout / setInterval with template-literal or req.*/body.*/query.*',
      '   • jwt.decode (no signature verification — token can be forged)',
      '   • Supabase service-role key on client-side createClient (bypasses RLS)',
      '   • LLM completion calls without max_tokens cap (cost-runaway via prompt injection)',
      '   • CORS Access-Control-Allow-Origin: *  combined with  Allow-Credentials: true',
    ],
    bypass: 'For a dangerous shell command to execute, either (a) the guard would need to be turned off (mode = off in destructive-guard.json — a one-line audit-able change to a tracked config file), (b) the command would need to not match any regex (the patterns are tuned for high-precision interception of the specific failure modes that vibe-coders most often regret — novel destructive commands are not caught), or (c) the user would need to run the command outside Claude Code in a regular terminal. The guard is a safety net, not an air gap.',
    extra: [
      'Hook surfaces active: ' + hooked.join(', ') + (hooked.length < 4 ? '  (some missing — run /install-hooks)' : ''),
      'Code-edit guard mode: ' + bodyguardCfg.mode + '   (block = refuse insecure edit; warn = log but allow; off = disabled)',
      'Shell guard mode: ' + destructCfg.mode + '   (block = refuse on critical; warn = log; off = disabled)',
      'User-extensible: both guards accept extraPatterns in their config file',
    ],
    evidence: 'hooks/pre-bash-guard.js  +  hooks/pre-edit-bodyguard.js  +  .agentic-security/{bodyguard,destructive-guard}.json',
  };
}

// ============================================================================
// 3. Feedback loops
// ============================================================================
function checkFeedback() {
  const postEdit = exists(path.join(pluginRoot, 'hooks', 'post-edit-scan.js'));
  const drift = exists(path.join(pluginRoot, 'hooks', 'session-stop-drift-check.js'));
  const lastScan = mtimeOf(path.join(cwd, '.agentic-security', 'last-scan.json'));
  const hist = exists(path.join(cwd, '.agentic-security', 'fix-history'));
  return {
    active: postEdit && drift ? 'on' : 'warn',
    what: [
      'Three feedback loops catch mistakes at different time horizons. The fastest is the post-edit scan: every time the agent writes or edits a file, the scanner re-runs on that file\\'s parent directory and reports any NEW high- or critical-severity findings the edit just introduced — typically within 1–2 seconds. The output is diffed against the baseline scan, so pre-existing findings do not generate noise; only freshly-introduced ones are surfaced.',
      'The second loop is fix-time verification: before any patch is committed via the apply_fix tool, an in-memory rescan of the patched file runs through the same detectors that produced the finding, plus the project linter. The fix is refused if the original problem ID is still present, or if a new ≥medium finding appeared as a side-effect of the change.',
      'The third loop runs at session end: the harness diffs the worktree against HEAD and flags structural drift — new modules added to source dirs that are not yet referenced in the documentation index. Combined with the continual-learning AGENTS.md nudge, this is the loop that catches \"agent wrote code, forgot to update the index\" failures before they ship.',
    ],
    blocks: [
      'Post-edit scan (hooks/post-edit-scan.js, throttled to 1 scan per file per 5 seconds):',
      '   • Runs after every Edit / Write / MultiEdit tool call',
      '   • Scans only the directory containing the edited file (fast — not the whole tree)',
      '   • Diffs against .agentic-security/last-scan.json to suppress pre-existing findings',
      '   • Reports NEW critical + high findings only',
      '   • One-line stderr output the agent sees in the next turn — and can act on',
      'Fix-time verification (verify_fix MCP tool):',
      '   • Re-runs the same detectors that produced the finding, on the patched file',
      '   • Runs the project linter',
      '   • Refuses to commit the change if:',
      '       - The original stableId is still present (the fix did not actually fix it), OR',
      '       - A new ≥medium finding appeared (the fix introduced a new vulnerability)',
      '   • 2-attempt retry budget per stableId — after which the finding routes to a human',
      'Session-stop drift detection (hooks/session-stop-drift-check.js):',
      '   • Diffs the worktree against HEAD at session end',
      '   • Flags new .js modules in sast/, posture/, dataflow/, mcp/ not indexed in the local CLAUDE.md',
      '   • Nudges to append to .agentic-security/AGENTS.md if the session touched tracked files',
      '   • Non-blocking — the warning surfaces but the session ends normally',
    ],
    bypass: 'A regression slipping past these loops would require either (a) the edit to land in a directory that scans cleanly even though a new vulnerability was introduced (a detector gap, not a process gap — every detector ships with a fixture pair so regressions in the detector itself are caught at CI time), (b) the fix to satisfy the same-stableId check while still containing the issue (the canonical fix is verbatim from the scan output and the verifier runs the literal detector again, so this requires defeating both verification paths simultaneously), or (c) the scan signature to be tampered with — which is caught by control #4.',
    extra: [
      'Post-edit scan hook: ' + (postEdit ? 'active' : 'MISSING'),
      'Session-stop drift hook: ' + (drift ? 'active' : 'MISSING'),
      'Last scan baseline timestamp: ' + (lastScan ? lastScan.toISOString() : 'NONE — run /scan --all to take one'),
      'Fix-attempt history present: ' + (hist ? 'yes (retry budget enforced)' : 'no (first run)'),
    ],
    evidence: 'hooks/post-edit-scan.js  +  scanner/src/mcp/tools.js (verify_fix)  +  scanner/src/posture/fix-history.js',
  };
}

// ============================================================================
// 4. Audit evidence
// ============================================================================
function checkAudit() {
  const auditLog = path.join(cwd, '.agentic-security', 'mcp-audit.log');
  const sigPath = path.join(cwd, '.agentic-security', 'last-scan.json.sig');
  const entries = lineCount(auditLog);
  const webhook = !!process.env.AGENTIC_SECURITY_AUDIT_WEBHOOK;
  const sig = exists(sigPath);
  return {
    active: entries > 0 || sig ? 'on' : 'warn',
    detail: '',
    what: [
      'Every MCP tool call the agent makes appends one line to a hash-chained audit log. The line contains: an ISO timestamp, a session ID, the tool name, the outcome (allowed / refused / error), the reason if refused, the call arguments (with credentials redacted), and the SHA-256 hash of the previous line. The very first entry chains to the literal string \"GENESIS\". Tampering with any line — editing it, deleting it, reordering — breaks the chain from that point forward, and a verifier (verifyAuditLog) walks the chain and returns the broken line index.',
      'In addition to the call-level trail, every scan output is signed with HMAC-SHA256 using a per-install random 32-byte key generated on first run and stored at \$XDG_CONFIG_HOME/agentic-security/scan-key with mode 0600. The key is NOT derived from the hostname or any predictable value. Downstream tools (apply_fix, /fix, /compliance-report) verify the signature before consuming the scan; a tampered findings file is silently refused.',
      'For tamper-evidence against a full-file rewrite of the local log (an attacker with FS write could re-author every line with fresh hashes), every audit entry is OPTIONALLY also POSTed fire-and-forget to a remote webhook configured via AGENTIC_SECURITY_AUDIT_WEBHOOK. Failures land in a sidecar error log so an operator can detect when the off-host witness is unreachable. Any gap between local-sequence and remote-sequence is evidence of a forging attempt.',
    ],
    blocks: [
      'Properties of the audit log:',
      '   • Format: NDJSON (one JSON object per line) at .agentic-security/mcp-audit.log',
      '   • Each entry: { ts, sessionId, tool, outcome, reason?, args, prev }',
      '   • sessionId = <pid>-<short-ts>  — disambiguates concurrent runs on one host',
      '   • prev = SHA-256 of the previous entry\\'s serialized JSON line  (first = \"GENESIS\")',
      '   • Argument redaction: every credential-shaped substring stripped from args before append',
      '   • Argument size cap: 1 KB per entry; longer args truncated with explicit byte-count suffix',
      '   • Audit failures NEVER block a tool call (would otherwise turn a disk-full into a DoS)',
      'Properties of the scan-output signature:',
      '   • Algorithm: HMAC-SHA256',
      '   • Key: 32 random bytes, mode 0600, stored OUTSIDE the repo at \$XDG_CONFIG_HOME',
      '   • Key override: \$AGENTIC_SECURITY_HMAC_KEY (hex) for CI environments',
      '   • Verification: every consumer of last-scan.json refuses on signature mismatch',
      '   • The same signature gates the rules.yml override file (see control #5)',
      'Properties of the remote witness (optional):',
      '   • Trigger: set AGENTIC_SECURITY_AUDIT_WEBHOOK to a POST endpoint',
      '   • Transport: HTTPS POST of the JSON entry; 1.5 second timeout',
      '   • Failure mode: error logged to mcp-audit.remote-errors.log, never blocks',
      '   • Forensic value: closes the full-file-rewrite blind spot — re-authoring the local log',
      '     does not re-create the off-host witness\\'s sequence',
      'Server-side trust anchors:',
      '   • MCP server reports its source SHA-256 fingerprint in every initialize response',
      '   • Clients can pin the build they trust and refuse downgrades',
    ],
    bypass: 'Forging the audit trail would require either (a) total filesystem write access PLUS the per-install HMAC key PLUS — if the remote witness is configured — control of the off-host endpoint OR ability to detect when the network is down and replay the same gap on the local side. Each layer adds independent friction. The remote witness is the most important one for high-stakes environments — without it, an attacker with FS write can re-author the local log silently; with it, every gap is visible from outside the host.',
    extra: [
      'Audit log entries (this project, this install): ' + entries,
      'Last-scan HMAC signature on disk: ' + (sig ? 'present' : 'ABSENT'),
      'Off-host audit witness: ' + (webhook ? 'CONFIGURED (AGENTIC_SECURITY_AUDIT_WEBHOOK set)' : 'not configured — set to a POST endpoint to enable'),
      'Verifier: import verifyAuditLog from scanner/src/mcp/audit.js  →  walks the chain, returns broken line index on tamper',
    ],
    evidence: '.agentic-security/mcp-audit.log  +  .agentic-security/last-scan.json.sig  +  scanner/src/mcp/audit.js (verifyAuditLog)',
  };
}

// ============================================================================
// 5. Failure mode
// ============================================================================
function checkFailure() {
  const rulesYml = safeRead(path.join(cwd, '.agentic-security', 'rules.yml'));
  const rulesSig = exists(path.join(cwd, '.agentic-security', 'rules.yml.sig'));
  const unsigned = process.env.AGENTIC_SECURITY_RULES_UNSIGNED === '1';
  return {
    active: 'on',
    what: [
      'The harness is refuse-by-default. When something the agent does fails verification, the answer is always to block the action and surface the reason — never to silently best-effort or partially-apply. There is no \"soft\" failure path that lets a bad fix land \"just in case\" the verifier is wrong.',
      'There are bounded budgets so a confused model cannot grind forever. Each finding has a 2-attempt fix budget; after both attempts fail verification, the finding is marked budget-exceeded and routed back to the supervisor (a human, or the calling agent that initiated the batch). Subagents are short-lived workers — one task per invocation — not long-running optimization loops; there is no context-compaction shim that lets a subagent keep grinding past its window.',
      'Coverage-reducing changes need a signature. The rules.yml override file can DISABLE detectors, but only if accompanied by a valid .sig signed with this install\\'s HMAC key. An unsigned override is silently ignored for any rule it tries to disable (with an explicit \"AGENTIC_SECURITY_RULES_UNSIGNED=1\" escape hatch for environments where signing is impractical). Severity-override and custom-rule entries are not gated — they expand coverage rather than shrink it.',
    ],
    blocks: [
      'Refusal points (the agent or the toolchain blocks rather than best-efforts):',
      '   • HMAC signature mismatch on last-scan.json  → all consumers refuse',
      '   • Reserved write-path target  → apply_fix refuses, edit-capable subagents refuse',
      '   • Path-escape (lexical .. or symlink-out-of-tree)  → _confine refuses pre-fs-call',
      '   • verify_fix reports original stableId still present  → apply_fix refuses',
      '   • verify_fix reports new ≥medium finding introduced  → apply_fix refuses',
      '   • MCP kill switch  AGENTIC_SECURITY_MCP_DISABLED=1  → every tool call refused',
      '   • Stdio line > 4 MB on the MCP transport  → drop-until-newline (DoS resistance)',
      '   • rules.yml disable: entry without valid .sig  → ignored, original detector keeps running',
      'Bounded budgets (a confused model cannot grind forever):',
      '   • 2 attempts per stableId, then [~] budget-exceeded → route to human supervisor',
      '   • Subagents are one task per invocation (no context-compaction loop)',
      '   • Recommended per-invocation batch sizes:',
      '       - security-fixer:  ≤ 10 findings  (each fix ≈ 5 tool calls; fits one context)',
      '       - refactor-cleaner:  ≤ 5 dead symbols  (each removal runs the full test suite)',
      '       - security-triager:  ≤ 30 findings  (read-only)',
      '       - security-poc-generator:  ≤ 5 findings  (PoC + regression test gen is verbose)',
      'Quarantine paths (experimental work cannot affect the gate):',
      '   • Custom rules with shadow:true  → write to shadow-findings.json',
      '   • Shadow findings are EXCLUDED from CI gates and counters',
      '   • LLM-validator outputs (opt-in via AGENTIC_SECURITY_LLM_VALIDATE=1) are non-blocking',
      'Calibration integrity (the confidence numbers cannot be self-fitted):',
      '   • Brier / ECE always computed on a held-out JSONL, never on the seed corpus',
      '   • Benchmark answer-key reading isolated to sast/bench-shape/ and OFF by default',
      '   • AGENTIC_SECURITY_BLIND_BENCH=1 forces bench-shape OFF even if a flag enabled it',
    ],
    bypass: 'For the harness to silently mis-apply a wrong fix, the verifier would need to report success while the detector still matches the same line. This requires either a detector bug (a regression in the rule that produced the finding) or a fix-history collision (two different findings sharing a stableId — defeated by the include-rule-id-in-stableId design). The 2-attempt budget caps the damage from either case at two writes per finding before a human is forced into the loop.',
    extra: [
      'Rules override present in this project: ' + (rulesYml ? 'yes' : 'no') + (rulesYml ? ('  (' + (rulesSig ? 'SIGNED' : (unsigned ? 'UNSIGNED — accepted because AGENTIC_SECURITY_RULES_UNSIGNED=1' : 'UNSIGNED — coverage-reducing entries are ignored')) + ')') : ''),
      'Retry budget: 2 attempts per finding, then routed to human',
      'Shadow mode available: yes (custom rules with shadow:true bypass CI gate)',
      'Calibration mode: held-out evaluation only',
    ],
    evidence: 'scanner/src/posture/{integrity,fix-history,holdout-eval}.js  +  .agentic-security/rules.yml(.sig)  +  scanner/src/sast/bench-shape/',
  };
}

// ============================================================================
// 6. Compliance
// ============================================================================
function checkCompliance() {
  const have = [];
  for (const f of ['SECURITY.md', 'compliance-report.md', 'compliance-attestation.json', 'sbom.json', 'sbom.cdx.json', 'aibom.json', 'sarif.json']) {
    if (exists(path.join(cwd, f))) have.push(f);
  }
  const reportsDir = path.join(cwd, 'reports');
  if (exists(reportsDir)) {
    try { for (const f of fs.readdirSync(reportsDir)) { if (/^(sbom|aibom|sarif|compliance)/i.test(f)) have.push('reports/' + f); } } catch {}
  }
  return {
    active: have.length ? 'on' : 'warn',
    what: [
      'The same scan engine that gates the agent\\'s edits emits machine-readable evidence on demand — without a separate, drift-prone compliance pipeline. The compliance artifacts are derived from the same findings the developers see day-to-day, so the auditor reads exactly what the agent enforced; there is no \"compliance view\" and \"engineering view\" that can disagree.',
      'Three frameworks are supported out of the box: NIST AI 600-1 (Generative AI Profile), OWASP ASVS (Application Security Verification Standard), and OWASP LLM Top 10 (2025). Each control in each framework is mapped to a specific set of detector outputs, so an auditor reading the report can drill from \"control 3.4.2\" all the way down to \"this specific finding in this specific file at this specific line.\"',
      'Re-runs are byte-identical when --deterministic is set: outputs sorted, no Date.now() in IDs, no per-run random suffixes. This means a signed attestation stays signed — re-running the scan to refresh evidence does not invalidate the signature, so audit-trail signatures persist across the lifetime of the engagement.',
    ],
    blocks: [
      'Frameworks supported by /compliance-report:',
      '   • NIST AI 600-1  (Generative AI Profile, 2024)',
      '   • OWASP ASVS    (Application Security Verification Standard, v4.0.3)',
      '   • OWASP LLM Top 10  (2025 release)',
      'Evidence formats emitted (machine-readable, CI-ingestable):',
      '   • SBOM in CycloneDX 1.5 JSON  (sbom.cdx.json)',
      '   • SBOM in SPDX 2.3 JSON       (sbom.json)',
      '   • AI-BOM  (aibom.json — model inventory, prompts-in-system surface, training-data refs)',
      '   • SARIF 2.1.0  (sarif.json — for GitHub Code Scanning, GitLab, Azure DevOps ingestion)',
      '   • Compliance attestation JSON  (compliance-attestation.json — per-control PASS/FAIL/N/A)',
      '   • Buyer-facing SECURITY.md  (one-pager for sales/diligence)',
      '   • Trust page (.well-known/security.txt + /security route)',
      'Determinism guarantees (so signed evidence stays signed):',
      '   • --deterministic produces byte-identical SARIF run-to-run',
      '   • All outputs sorted by stableId before emit',
      '   • No Date.now() in finding identifiers',
      '   • Same input + same scanner version + --deterministic → same SHA-256 output',
      'Auditor drill-down workflow:',
      '   1. Read SECURITY.md for the one-pager',
      '   2. Read compliance-attestation.json for per-control verdict',
      '   3. For any FAIL, follow the stableId pointers into sarif.json to see the exact finding',
      '   4. From the finding, run /why-fired <id> for full provenance (detector, rule, evidence)',
      'Coverage gaps the harness will NOT pretend to close (honest):',
      '   • SOC 2 process controls (vendor management, change management) — out of scope',
      '   • Penetration-testing report — out of scope (this is SAST + dataflow, not DAST)',
      '   • Privacy data-mapping — partial (/privacy-docs and /privacy-data-flow cover the code side)',
    ],
    bypass: 'A compliance report can be made misleading only by (a) running it against a sanitized fork of the codebase rather than the production codebase — defeated by versioning the scan output alongside source releases, (b) running with relaxed rules — defeated by control #5\\'s signed-override requirement, or (c) editing the report after generation — defeated by signing the attestation JSON with the same per-install HMAC key. Each defeat path is auditable.',
    extra: [
      have.length ? ('Compliance evidence found in this project:\n     - ' + have.join('\n     - ')) : 'No evidence files generated yet — run /compliance-report or /security-attestation to produce them',
      'Frameworks supported out of the box: NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10 (2025)',
      'Determinism: --deterministic flag available for byte-identical re-runs',
    ],
    evidence: 'commands/{compliance-report,security-attestation,privacy-docs}.md  +  scanner/src/report/  +  scripts/ci-templates/',
  };
}

// ============================================================================
// rendering
// ============================================================================
const W = (s, code) => (process.stdout.isTTY && format === 'text') ? '\\x1b[' + code + 'm' + s + '\\x1b[0m' : s;
const BOLD = '1', RED = '31', YELLOW = '33', GREEN = '32', DIM = '2';

function statusGlyph(s) {
  if (s === 'on')   return W('● ACTIVE',   GREEN);
  if (s === 'warn') return W('◐ PARTIAL', YELLOW);
  if (s === 'off')  return W('○ OFF',     RED);
  return W('? UNKNOWN', DIM);
}

function wrap(text, indent, width) {
  const out = [];
  const words = text.split(/\s+/);
  let row = indent;
  for (const w of words) {
    if (row.length + 1 + w.length > width) { out.push(row); row = indent + w; }
    else { row = row === indent ? row + w : row + ' ' + w; }
  }
  if (row.trim()) out.push(row);
  return out;
}

const sections = [
  ['1. Tool access — what the agent can and cannot run',         checkToolAccess()],
  ['2. Guardrails — forbidden commands, enforced limits',        checkGuardrails()],
  ['3. Feedback loops — what catches mistakes in flight',        checkFeedback()],
  ['4. Audit evidence — continuous proof of control',            checkAudit()],
  ['5. Failure mode — what happens when the model is wrong',     checkFailure()],
  ['6. Compliance — evidence generated automatically',           checkCompliance()],
];

function renderText() {
  const lines = [];
  const proj = path.basename(cwd);
  const W2 = 92;
  lines.push('');
  lines.push(W('━━━ Agent Harness Assessment ━━━', BOLD));
  lines.push('  Project: ' + proj);
  lines.push('  Generated: ' + new Date().toISOString());
  lines.push('  Audience: CISO / security reviewer / buyer questionnaire');
  lines.push('');
  lines.push(W('  Plain English. No CWE numbers. No CVSS. Six controls.', DIM));
  lines.push('');
  for (const [title, c] of sections) {
    lines.push(W(title, BOLD) + '   ' + statusGlyph(c.active));
    lines.push('');
    // What it does — multi-paragraph
    lines.push(W('   What it does', BOLD));
    for (const para of (c.what || [])) {
      for (const row of wrap(para, '   ', W2)) lines.push(row);
      lines.push('');
    }
    // Specifically — the enumerated list
    lines.push(W('   Specifically — what it allows / blocks / intercepts', BOLD));
    for (const line of (c.blocks || [])) {
      // If the entry starts with a 'header:' shape, render bold; if it's an indented bullet, keep
      if (/^[A-Z].*:$/.test(line) || /(:)$/.test(line.trim())) lines.push('   ' + line);
      else lines.push('   ' + line);
    }
    lines.push('');
    // Bypass
    lines.push(W('   What would have to go wrong for this to fail', BOLD));
    for (const row of wrap(c.bypass || '', '   ', W2)) lines.push(row);
    lines.push('');
    // Live status
    lines.push(W('   Live status (this project)', BOLD));
    for (const ex of (c.extra || [])) {
      const sub = ex.split('\\n');
      for (let i = 0; i < sub.length; i++) lines.push(i === 0 ? ('     · ' + sub[i]) : ('       ' + sub[i]));
    }
    lines.push('');
    lines.push(W('   Evidence: ', DIM) + W(c.evidence, DIM));
    lines.push('');
    lines.push(W('   ' + '─'.repeat(W2 - 3), DIM));
    lines.push('');
  }
  lines.push(W('━━━ What to do with this ━━━', BOLD));
  lines.push('  Hand this to: a CISO, a security buyer, an SOC 2 auditor, a Series A diligence team.');
  lines.push('');
  lines.push('  Drill-down commands a reviewer can run themselves:');
  lines.push('     /scan --all                — list every finding with severity');
  lines.push('     /show-findings --kev       — only the ones being weaponized today');
  lines.push('     /compliance-report         — NIST AI 600-1 / OWASP ASVS / OWASP LLM Top 10');
  lines.push('     /security-attestation      — one-page buyer-facing artifact');
  lines.push('     /why-fired <finding-id>    — provenance graph for any specific finding');
  lines.push('');
  return lines.join('\\n');
}

function renderMarkdown() {
  const lines = [];
  const proj = path.basename(cwd);
  lines.push('# Agent Harness Assessment');
  lines.push('');
  lines.push('- **Project:** ' + proj);
  lines.push('- **Generated:** ' + new Date().toISOString());
  lines.push('- **Audience:** CISO / security reviewer / buyer questionnaire');
  lines.push('');
  lines.push('> Plain English. No CWE numbers. No CVSS. Six controls. Each control has four named subsections: what it does, what it specifically blocks, what would have to go wrong for it to fail, and the live status from current project state.');
  lines.push('');
  for (const [title, c] of sections) {
    const badge = c.active === 'on' ? '✅ ACTIVE' : c.active === 'warn' ? '🟡 PARTIAL' : c.active === 'off' ? '🛑 OFF' : '❔';
    lines.push('## ' + title + '  ' + badge);
    lines.push('');
    lines.push('### What it does');
    lines.push('');
    for (const para of (c.what || [])) { lines.push(para); lines.push(''); }
    lines.push('### Specifically — what it allows / blocks / intercepts');
    lines.push('');
    lines.push('\`\`\`');
    for (const line of (c.blocks || [])) lines.push(line);
    lines.push('\`\`\`');
    lines.push('');
    lines.push('### What would have to go wrong for this to fail');
    lines.push('');
    lines.push(c.bypass || '');
    lines.push('');
    lines.push('### Live status (this project)');
    lines.push('');
    for (const ex of (c.extra || [])) lines.push('- ' + ex);
    lines.push('');
    lines.push('_Evidence:_ \`' + c.evidence + '\`');
    lines.push('');
    lines.push('---');
    lines.push('');
  }
  lines.push('## Drill-down commands a reviewer can run');
  lines.push('');
  lines.push('| Command | What it shows |');
  lines.push('|---|---|');
  lines.push('| \`/scan --all\` | every finding with severity |');
  lines.push('| \`/show-findings --kev\` | only the ones being weaponized today |');
  lines.push('| \`/compliance-report\` | NIST AI 600-1 / OWASP ASVS / OWASP LLM Top 10 |');
  lines.push('| \`/security-attestation\` | one-page buyer-facing artifact |');
  lines.push('| \`/why-fired <id>\` | provenance graph for any specific finding |');
  lines.push('');
  return lines.join('\\n');
}

const out = (format === 'md') ? renderMarkdown() : renderText();

if (outPath) {
  fs.writeFileSync(outPath, out);
  console.log('Wrote ' + outPath + '  (' + out.length + ' bytes, format=' + format + ')');
} else {
  process.stdout.write(out + '\\n');
}
" -- "$@"
```

Print the output verbatim. The user wants a single self-contained briefing
they can read in ten to fifteen minutes or paste into a buyer questionnaire.

---

## Interactive compliance step (DO this after printing the assessment)

After the bash block prints the six-control assessment, the **Compliance**
section (#6) only summarizes what evidence COULD be produced. To produce
the actual artifact on disk for an auditor, the model MUST run the
follow-up step below — do not skip it.

1. Call the AskUserQuestion tool with a single multiSelect question:

   - **question:** "Which compliance reports do you want generated now?"
   - **header:** "Frameworks"
   - **multiSelect:** true
   - **options** (exactly these four; user can pick zero, one, two, or all three):
     - **NIST AI 600-1** — Generative AI Profile, 122 controls
     - **OWASP ASVS** — Application Security Verification Standard
     - **OWASP LLM Top 10 (2025)** — 10 GenAI/LLM risk controls
     - **None right now** — skip artifact generation

2. For each framework the user selects, run `/compliance-report <fw>` with
   the matching positional argument (the command takes ONE positional):

   | User's selection | `/compliance-report` argument |
   |---|---|
   | NIST AI 600-1 | `nist` |
   | OWASP ASVS | `asvs` |
   | OWASP LLM Top 10 | `llm` |

   Invoke each via the Skill tool — `skill: "agentic-security:compliance-report"`,
   `args: "<fw>"` — once per selected framework, sequentially (not in parallel,
   so the artifact files don't race on stdout). If the user selected "None right
   now", do not invoke /compliance-report; instead confirm "skipping compliance
   artifact generation — you can run /compliance-report later" and end the turn.

3. After all selected reports complete, tell the user which artifacts now
   exist on disk (the report command writes to predictable filenames:
   `nist-ai-600-1-attestation.md`, `owasp-asvs-attestation.md`,
   `owasp-llm-top10-attestation.md`).

This interactive step is the difference between "the agent harness CAN emit
compliance evidence" (the Compliance section's claim) and "compliance
evidence exists on disk right now" — auditors only accept the latter.

---

## Notes for downstream use

- **Default format is plain text** with ANSI color for terminal reading.
  `--format md` switches to GitHub-flavored markdown. `--output PATH`
  implies `--format md` and writes to that path (typical:
  `AGENT_HARNESS_ASSESSMENT.md`).
- **Live evidence.** The "Live status (this project)" subsection of each
  control is derived from current state — hooks wired, scan signed, audit
  log entry count, remote witness configured, compliance artifacts present.
  The reviewer is reading the *current* posture, not a generic template.
- **The four subsections per control** are deliberate, modeled on
  `/explain`'s plain-English narrative shape:
  - **What it does** — the control in 2–3 sentences of plain English.
  - **Specifically** — the concrete enumerated list of allows / blocks /
    intercepts. This is where a reviewer who wants to verify "yes the
    harness actually rejects `rm -rf /`" finds the proof.
  - **What would have to go wrong** — the threat model in one paragraph.
    Honest about what the control does NOT cover.
  - **Live status** — verifiable indicators a reviewer can re-derive.
- **No CWE numbers, no CVSS, no security jargon in the narrative prose.**
  The "Specifically" block names the actual file paths, commands, and
  patterns — those are necessarily concrete — but the connective tissue
  is written for an executive reader.
- **What it is not.** This is the controls report. It is not the
  findings report (`/scan --all`) or the grade (`/report-card`). It
  routes INTO `/compliance-report` for framework-specific attestations
  via the interactive step above.
