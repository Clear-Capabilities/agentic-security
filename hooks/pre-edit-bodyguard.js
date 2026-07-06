#!/usr/bin/env node
// PreToolUse hook: scan the content the agent is ABOUT to write, before it
// hits disk. Block (or warn) on critical patterns so insecure AI-generated
// code never lands.
//
// Behavior controlled by .agentic-security/bodyguard.json:
//   { "mode": "warn" | "block" | "off", "skipPaths": ["test/", "fixtures/"] }
// Default mode: "warn". Set "block" to fail the edit on critical findings.
//
// Per-project forbidden APIs at .agentic-security/forbidden-apis.yml:
//   bans:
//     - pattern: "\\beval\\s*\\("
//       message: "eval() is banned org-wide; use a parser library"
//     - pattern: "\\blegacyDb\\."
//       message: "legacyDb is deprecated; use db.* instead"
//
// Plain CommonJS — zero deps beyond the standard library.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cfgPath = path.join(stateDir, 'bodyguard.json');

function readCfg() {
  const defaults = { mode: 'warn', skipPaths: ['test/', 'tests/', '__tests__/', 'fixtures/', 'node_modules/'] };
  try {
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    // Merge — user-supplied keys override defaults; user-omitted keys fall back.
    return { ...defaults, ...parsed };
  } catch { return defaults; }
}

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

// Fast in-memory rules — high-precision, low-FP patterns that vibe-coders
// most often ship unintentionally. The full scanner runs post-edit; this is
// the just-in-time gate for the obviously-dangerous stuff.
const RULES = [
  {
    id: 'sqli-string-concat',
    name: 'SQL injection (string concatenation)',
    severity: 'critical',
    re: /(?:db|connection|client|knex|pool|sequelize)\s*\.\s*(?:query|raw|execute)\s*\(\s*[`'"][^`'"]*\$\{|(?:db|connection|client)\s*\.\s*(?:query|raw|execute)\s*\(\s*['"][^'"]*['"]\s*\+\s*\w+/i,
    hint: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [id])` — never string-concat user input.',
  },
  {
    id: 'cmd-injection',
    name: 'Shell command injection',
    severity: 'critical',
    re: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`'"][^`'"]*\$\{|(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*\+|.*\+\s*\w+)/,
    hint: 'Never interpolate user input into a shell string. Pass argv as an array: `spawn("ls", [userPath], {shell: false})`.',
  },
  {
    id: 'next-public-secret',
    name: 'Secret leaked to client (NEXT_PUBLIC_)',
    severity: 'critical',
    re: /NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|API_KEY|ANTHROPIC|OPENAI|STRIPE_SECRET|SUPABASE_SERVICE)/i,
    hint: 'Anything prefixed `NEXT_PUBLIC_` ships to the browser. Move this to a non-public env var and access it only in a server route.',
  },
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded credential',
    severity: 'critical',
    re: /(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\s*[:=]\s*['"`](?:sk-[A-Za-z0-9-]{20,}|ghp_[A-Za-z0-9]{30,}|xoxb-[A-Za-z0-9-]{30,}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}|pk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,})['"`]/i,
    hint: 'Move this credential to an env var (e.g. `process.env.OPENAI_API_KEY`) and add the value to .env (which must be in .gitignore).',
  },
  {
    id: 'dangerous-html',
    name: 'XSS via dangerouslySetInnerHTML',
    severity: 'high',
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitize)/,
    hint: 'Pass user input through DOMPurify.sanitize() before injecting as HTML, or render as text instead.',
  },
  {
    id: 'eval-user-input',
    name: 'eval / new Function with user input',
    severity: 'critical',
    re: /(?:^|[^.\w])(?:eval|Function|setTimeout|setInterval)\s*\(\s*[`'"][^`'"]*\$\{|(?:^|[^.\w])(?:eval|Function)\s*\(\s*(?:req\.|request\.|input|userInput|user_input|params\.|body\.|query\.)/,
    hint: 'eval()/new Function() on user input is RCE. Use JSON.parse, a parser library, or refactor to not need dynamic code.',
  },
  {
    id: 'jwt-no-verify',
    name: 'JWT decoded without signature verification',
    severity: 'high',
    re: /(?:jwt|jsonwebtoken)\s*\.\s*decode\s*\(/,
    hint: 'jwt.decode() does NOT verify the signature. Use jwt.verify(token, secret) — otherwise the token can be forged.',
  },
  {
    id: 'service-role-client',
    name: 'Supabase service-role key on the client',
    severity: 'critical',
    re: /createClient\s*\([^,]+,\s*[^,)]*(?:SERVICE_ROLE|service_role|SUPABASE_SERVICE)/i,
    hint: 'The service-role key bypasses RLS. Use it only in server-side code; for client use SUPABASE_ANON_KEY.',
  },
  {
    id: 'no-max-tokens',
    name: 'LLM call without max_tokens (cost runaway)',
    severity: 'high',
    re: /(?:anthropic|openai)\s*\.\s*(?:messages|chat\.completions|completions)\s*\.\s*create\s*\(\s*\{[^}]*model\s*:\s*['"`][^'"`]+['"`][^}]*\}\s*\)/m,
    requires: c => !/max_tokens\s*:/m.test(c),
    hint: 'LLM call has no max_tokens cap — one prompt-injection attack could cost thousands. Add e.g. `max_tokens: 1024`.',
  },
  {
    id: 'cors-wildcard-credentials',
    name: 'CORS wildcard with credentials',
    severity: 'critical',
    re: /Access-Control-Allow-Origin['"`]?\s*[:,]\s*['"`]\*['"`][\s\S]{0,200}Access-Control-Allow-Credentials['"`]?\s*[:,]\s*['"`]?true/i,
    hint: 'Wildcard origin + credentials is forbidden by spec and bypasses same-origin protections. Set Origin to a specific domain.',
  },
  {
    id: 'pickle-untrusted',
    name: 'pickle.load / pickle.loads on untrusted input',
    severity: 'critical',
    re: /\bpickle\.(?:load|loads)\s*\(\s*(?:request\.|flask\.request|requests\.get|requests\.post|input\(|sys\.stdin|os\.environ|open\s*\(\s*[^)]*(?:request|user|input))/,
    hint: 'pickle deserializes arbitrary Python objects — RCE on untrusted input. Use JSON or MessagePack.',
  },
  {
    id: 'tls-no-verify',
    name: 'TLS certificate verification disabled',
    severity: 'critical',
    re: /\brejectUnauthorized\s*:\s*false\b|\bInsecureSkipVerify\s*:\s*true\b|\brequests\.(?:get|post|put|delete|patch)\s*\([^)]*verify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0/,
    hint: 'TLS without cert verification reduces TLS to obfuscation. Pin the CA: `ca: fs.readFileSync("ca.pem")` / `verify="/path/to/ca.pem"`.',
  },
  {
    id: 'ssrf-cloud-metadata',
    name: 'SSRF to cloud metadata endpoint (169.254.169.254)',
    severity: 'critical',
    re: /(?:fetch|axios|requests\.get|http\.get|urlopen)\s*\(\s*[`'"][^`'"]*(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)/,
    hint: 'Cloud instance metadata exposes IAM credentials. If you need a metadata call, hardcode the URL — never let user input control the host.',
  },
  {
    id: 'path-traversal-template',
    name: 'Path traversal via unvalidated user input',
    severity: 'critical',
    re: /(?:fs|fsp|fs\/promises)\.(?:readFile|writeFile|unlink|rm|createReadStream|createWriteStream)(?:Sync)?\s*\(\s*(?:`[^`]*\$\{(?:req\.|request\.|input|userInput|user_input|params\.|body\.|query\.|process\.argv)|['"]\s*\+\s*(?:req\.|request\.|input|userInput|user_input|params\.|body\.|query\.))/,
    hint: 'Resolve to absolute path + assert under a trusted root: `const safe = path.resolve(root, name); if (!safe.startsWith(root + path.sep)) throw new Error("path escape");`.',
  },
  {
    id: 'react-href-javascript',
    name: 'href={`javascript:${userInput}`} (XSS via href)',
    severity: 'high',
    re: /href\s*=\s*\{?\s*[`'"]javascript:\$?\{?(?:req\.|request\.|input|userInput|user_input|params\.|body\.|query\.|props\.)/,
    hint: 'javascript:-URLs in href run any JS the attacker supplies. Use onClick handlers, never href.',
  },
  {
    id: 'md5-sha1-password',
    name: 'MD5 / SHA1 used to hash a password',
    severity: 'critical',
    re: /(?:createHash|hashlib\.|MessageDigest\.getInstance|MD5|SHA1)[\s\S]{0,200}(?:password|passwd|pwd)\b/i,
    hint: 'MD5/SHA1 are broken for password hashing. Use Argon2id (preferred), bcrypt (cost ≥ 12), or scrypt.',
  },
  {
    id: 'jwt-none-alg',
    name: 'JWT verify accepting alg: "none"',
    severity: 'critical',
    re: /jwt\.(?:verify|decode)\s*\([^)]*algorithms?\s*:\s*\[[^\]]*['"]none['"]/i,
    hint: 'alg=none means no signature verification. Pin algorithms: `jwt.verify(token, key, { algorithms: ["RS256"] })`.',
  },
];

// Per-project bans loaded from .agentic-security/forbidden-apis.yml (or .json
// for users who don't want a YAML parser dependency). Each entry is a regex
// + message. Triggers behave like a 'critical' rule.
function loadForbiddenApis() {
  for (const name of ['forbidden-apis.yml', 'forbidden-apis.yaml', 'forbidden-apis.json']) {
    const fp = path.join(stateDir, name);
    if (!fs.existsSync(fp)) continue;
    try {
      const raw = fs.readFileSync(fp, 'utf8');
      // Minimal YAML subset: lines like `- pattern: "..."` / `  message: "..."`.
      // For JSON, do a real parse.
      if (name.endsWith('.json')) {
        const j = JSON.parse(raw);
        return (j.bans || []).map(b => ({ pattern: b.pattern, message: b.message }));
      }
      const bans = [];
      const blocks = raw.split(/^\s*-\s*pattern:/m).slice(1);
      for (const b of blocks) {
        const patMatch = b.match(/^\s*['"]([^'"]+)['"]/);
        const msgMatch = b.match(/message\s*:\s*['"]([^'"]+)['"]/);
        if (patMatch) bans.push({ pattern: patMatch[1], message: msgMatch ? msgMatch[1] : 'Forbidden API used' });
      }
      return bans;
    } catch { return []; }
  }
  return [];
}

function scan(content, filePath) {
  const findings = [];
  for (const r of RULES) {
    if (r.requires && !r.requires(content)) continue;
    const m = r.re.exec(content);
    if (m) {
      const before = content.slice(0, m.index);
      const line = before.split('\n').length;
      findings.push({ id: r.id, name: r.name, severity: r.severity, hint: r.hint, line, sample: m[0].slice(0, 120) });
    }
  }
  // Per-project forbidden APIs — treat as critical bans.
  for (const ban of loadForbiddenApis()) {
    try {
      const re = new RegExp(ban.pattern);
      const m = re.exec(content);
      if (m) {
        const before = content.slice(0, m.index);
        const line = before.split('\n').length;
        findings.push({
          id: 'forbidden-api',
          name: 'Forbidden API (per-project ban)',
          severity: 'critical',
          hint: ban.message,
          line, sample: m[0].slice(0, 120),
        });
      }
    } catch {} // bad regex in user config — skip
  }
  return findings;
}

function formatFindings(findings, filePath, mode) {
  const rel = path.relative(cwd, filePath);
  const headLine = mode === 'block'
    ? `🛑 agentic-security bodyguard: BLOCKED edit to ${rel}`
    : `⚠️  agentic-security bodyguard: ${findings.length} security risk(s) in proposed edit to ${rel}`;
  const lines = [headLine, ''];
  for (const f of findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.name}  (line ${f.line})`);
    lines.push(`     match: ${f.sample.replace(/\n/g, ' ')}`);
    lines.push(`     ${f.hint}`);
    lines.push('');
  }
  if (mode === 'block') {
    lines.push('Edit blocked. To override, either fix the issue, or change');
    lines.push('  .agentic-security/bodyguard.json  →  { "mode": "warn" }');
  } else {
    lines.push('(Edit allowed in warn mode. Set bodyguard.json mode="block" to enforce.)');
  }
  return lines.join('\n');
}

// Pure evaluator — importable so the single PreToolUse dispatcher (#24) can run
// the guard in-process and short-circuit on a block, without a second process
// spawn. Returns { action: 'allow' | 'warn' | 'block', message? }; the IIFE below
// maps that to the exact same exit codes / stderr the standalone hook used.
async function evaluate(evt) {
  const cfg = readCfg();
  if (cfg.mode === 'off') return { action: 'allow' };

  const tool = evt.tool_name || evt.toolName;
  if (!['Edit', 'Write', 'MultiEdit'].includes(tool)) return { action: 'allow' };

  const input = evt.tool_input || {};
  const filePath = input.file_path || input.filePath || '';
  if (!filePath) return { action: 'allow' };
  const rel = path.relative(cwd, filePath);
  if (rel.startsWith('..')) return { action: 'allow' };

  for (const skip of (cfg.skipPaths || [])) {
    if (rel.includes(skip)) return { action: 'allow' };
  }

  // Determine the proposed content depending on the tool variant
  let proposedContent = '';
  if (tool === 'Write') {
    proposedContent = input.content || '';
  } else if (tool === 'Edit') {
    proposedContent = input.new_string || '';
  } else if (tool === 'MultiEdit') {
    proposedContent = (input.edits || []).map(e => e.new_string || '').join('\n');
  }
  if (!proposedContent || proposedContent.length < 8) return { action: 'allow' };

  const findings = scan(proposedContent, filePath);
  if (!findings.length) return { action: 'allow' };
  const crit = findings.filter(f => f.severity === 'critical');
  const message = formatFindings(findings, filePath, cfg.mode);

  // Block only on a critical finding in block mode; otherwise warn (edit proceeds).
  if (cfg.mode === 'block' && crit.length > 0) return { action: 'block', message };
  return { action: 'warn', message };
}

async function main() {
  const evt = await readStdinJSON();
  const d = await evaluate(evt);
  if (d.action === 'block') {
    // Exit code 2 + stderr message is the PreToolUse "deny" signal in Claude Code.
    process.stderr.write(d.message + '\n');
    process.exit(2);
  }
  if (d.action === 'warn') {
    process.stderr.write(d.message + '\n');
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = { evaluate };
