// Environment hygiene checker.
//
// Vibecoders leak secrets through env files: .env committed to git,
// NEXT_PUBLIC_ vars that expose private values, .env.example with real
// credentials, and hardcoded fallback values that look real.
//
// Findings (4 implemented; ENV_MISSING_GITIGNORE was documented here but has
// no implementation anywhere in this file — found via Stage-0 doc audit,
// 2026. Either implement it or drop it from this list; left as a gap, not
// silently removed, so the missing coverage stays visible):
//   ENV_NEXT_PUBLIC_SECRET     — NEXT_PUBLIC_ variable whose name implies it's secret
//   ENV_EXAMPLE_REAL_VALUE     — .env.example / .env.sample with a real-looking value
//   ENV_HARDCODED_FALLBACK     — process.env.X || "looks-real" fallback in source
//   ENV_DOTENV_IN_SOURCE       — .env file content loaded via require/import in prod code
//   NOT IMPLEMENTED: ENV_MISSING_GITIGNORE — .env / .env.local present but not in .gitignore

const _ENV_FILE_RE = /^\.env(?:\.(?:local|development|production|test|staging))?$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;

// NEXT_PUBLIC_ variables whose name implies they are secrets
const NEXT_PUBLIC_SENSITIVE_RE = /NEXT_PUBLIC_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|API_KEY|PRIVATE|SIGNING|WEBHOOK|SALT|SEED)\w*/gi;

// .env.example / .env.sample with non-placeholder values
// A "real" value is: not empty, not "xxx...", not "your_...", not "<...>", not "changeme", not "placeholder"
const ENV_EXAMPLE_RE = /^\.env\.(?:example|sample|template)$/i;
const PLACEHOLDER_RE = /^(?:|xxx+|your[_-]|<[^>]+>|changeme|change[_-]?me|placeholder|todo|fixme|replace|dummy|fake|test|example|sample|n\/a|none|null|undefined|\$\{[^}]+\})$/i;
const REAL_VALUE_RE = /^[a-zA-Z0-9+/=_\-]{8,}$/; // looks like an actual token/key

// process.env.X || "fallback" where fallback looks real (not empty string, not "localhost", not "3000")
const HARDCODED_FALLBACK_RE = /process\.env\.(\w+)\s*\|\|\s*['"`]([^'"`]{4,})['"`]/g;
const BENIGN_FALLBACK_RE = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|3000|8080|8000|production|development|test|info|debug|warn|error|true|false|\/|\.|\s*)$/i;

// require('dotenv') / import dotenv in non-config files
const DOTENV_IMPORT_RE = /(?:from|require)\s*\(?\s*['"`]dotenv['"`]/;
const CONFIG_FILE_RE = /(?:^|\/)(?:config|env|\.env|setup|bootstrap|init|app)\.[cm]?[jt]s$/i;

function _lineNumber(content, index) {
  return content.slice(0, index).split('\n').length;
}

function scanEnvHygiene(file, content) {
  if (_NONPROD_RE.test(file)) return [];
  const findings = [];
  const basename = file.split('/').pop();
  const isEnvExample = ENV_EXAMPLE_RE.test(basename);
  const isEnvFile = _ENV_FILE_RE.test(basename);
  const isJsTs = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file);

  // --- NEXT_PUBLIC_ with sensitive name ---
  if (isEnvFile || isEnvExample || isJsTs) {
    const matches = [...content.matchAll(new RegExp(NEXT_PUBLIC_SENSITIVE_RE.source, 'gi'))];
    for (const m of matches) {
      const lineNum = _lineNumber(content, m.index);
      findings.push({
        id: `env-hygiene:ENV_NEXT_PUBLIC_SECRET:${file}:${lineNum}`,
        title: `NEXT_PUBLIC_ variable exposes a sensitive value client-side: ${m[0]}`,
        severity: 'critical',
        file, line: lineNum,
        description: `${m[0]} is prefixed with NEXT_PUBLIC_, which means Next.js will bundle its value into the client-side JavaScript. Any visitor can read it from the page source. Variables named SECRET, KEY, TOKEN, or similar should never be public.`,
        remediation: 'Remove the NEXT_PUBLIC_ prefix. Access this value only in Server Components, API Routes, or Server Actions where it stays on the server.',
        cwe: 'CWE-522',
      });
    }
  }

  // --- .env.example with real values ---
  if (isEnvExample) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;
      const eqIdx = line.indexOf('=');
      if (eqIdx === -1) continue;
      const value = line.slice(eqIdx + 1).trim().replace(/^['"`]|['"`]$/g, '');
      if (value && !PLACEHOLDER_RE.test(value) && REAL_VALUE_RE.test(value)) {
        findings.push({
          id: `env-hygiene:ENV_EXAMPLE_REAL_VALUE:${file}:${i + 1}`,
          title: '.env.example contains a real-looking credential value',
          severity: 'high',
          file, line: i + 1,
          description: `Line ${i + 1} in ${basename} has a value that looks like a real secret rather than a placeholder. If this is an actual credential, it is now permanently in git history.`,
          remediation: 'Replace real values with descriptive placeholders: `API_KEY=your_api_key_here` or `DATABASE_URL=postgres://user:pass@host/db`. Rotate the leaked credential immediately.',
          cwe: 'CWE-798',
        });
      }
    }
  }

  // --- process.env.X || "real-fallback" in source ---
  if (isJsTs) {
    let m;
    const re = new RegExp(HARDCODED_FALLBACK_RE.source, 'g');
    while ((m = re.exec(content)) !== null) {
      const [, varName, fallback] = m;
      if (BENIGN_FALLBACK_RE.test(fallback)) continue;
      // Skip if the variable name is obviously benign
      if (/^(?:NODE_ENV|PORT|HOST|LOG_LEVEL|TIMEOUT|DEBUG|NEXT_PUBLIC_APP_URL|APP_URL|BASE_URL|PUBLIC_URL)\b/.test(varName)) continue;
      const lineNum = _lineNumber(content, m.index);
      findings.push({
        id: `env-hygiene:ENV_HARDCODED_FALLBACK:${file}:${lineNum}`,
        title: `Hardcoded fallback for ${varName} looks like a real credential`,
        severity: 'high',
        file, line: lineNum,
        description: `process.env.${varName} falls back to "${fallback.slice(0, 20)}${fallback.length > 20 ? '...' : ''}" when the env var is unset. If this value is a real secret, it is committed to source and will be used silently when the env var is misconfigured in production.`,
        remediation: `Remove the fallback: throw an error at startup if ${varName} is unset. Use a config validation library like zod or @t3-oss/env-nextjs to enforce required env vars.`,
        cwe: 'CWE-798',
      });
    }
  }

  // --- dotenv imported outside of config/entry files ---
  if (isJsTs && !CONFIG_FILE_RE.test(file) && DOTENV_IMPORT_RE.test(content)) {
    const lineNum = _lineNumber(content, content.search(DOTENV_IMPORT_RE));
    findings.push({
      id: `env-hygiene:ENV_DOTENV_IN_SOURCE:${file}:${lineNum}`,
      title: 'dotenv loaded in non-entry file',
      severity: 'low',
      file, line: lineNum,
      description: 'dotenv.config() in a non-entry module can silently load .env files in production, overriding real environment variables set by your platform. It also makes testing harder.',
      remediation: 'Call dotenv.config() only once, in your application entry point (server.js, index.js). Better yet, use platform-native env management (Vercel env vars, Railway variables).',
      cwe: 'CWE-665',
    });
  }

  return findings;
}

export { scanEnvHygiene };
