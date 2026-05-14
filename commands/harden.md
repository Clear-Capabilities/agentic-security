---
description: One-command security hardening — automatically applies safe infrastructure fixes to your project (security headers, .gitignore, cookie flags, npm audit hook).
---

Apply a curated set of safe, automated security improvements to the project. Unlike `/fix` (which patches specific findings), `/harden` proactively adds best-practice scaffolding that isn't a finding yet: security headers, environment protection, and CI hooks.

```bash
node -e "
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let applied = [], skipped = [], failed = [];

function tryApply(label, fn) {
  try {
    const result = fn();
    if (result === 'skip') skipped.push(label);
    else applied.push(label);
  } catch (e) {
    failed.push(label + ': ' + e.message);
  }
}

// ── 1. Add .env* to .gitignore ───────────────────────────────────────────────
tryApply('Add .env* to .gitignore', () => {
  const gi = fs.existsSync('.gitignore') ? fs.readFileSync('.gitignore', 'utf8') : '';
  const needed = ['.env', '.env.local', '.env.*.local', '.env.production', '.env.development'];
  const missing = needed.filter(p => !gi.includes(p));
  if (missing.length === 0) return 'skip';
  const toAdd = '\n# Environment files — added by agentic-security /harden\n' + missing.join('\n') + '\n';
  fs.appendFileSync('.gitignore', toAdd);
});

// ── 2. Add security headers to next.config.js ────────────────────────────────
tryApply('Security headers in next.config.js', () => {
  const cfgCandidates = ['next.config.js', 'next.config.ts', 'next.config.mjs'];
  const cfgPath = cfgCandidates.find(f => fs.existsSync(f));
  if (!cfgPath) return 'skip';
  const src = fs.readFileSync(cfgPath, 'utf8');
  if (/X-Frame-Options|Content-Security-Policy/.test(src)) return 'skip';
  // Find the module.exports / export default object and inject headers() before it
  const headerBlock = \`
// Security headers added by agentic-security /harden
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
];
\`;
  // Insert before the config export
  const exportIdx = src.search(/(?:module\.exports\s*=|export\s+default)/);
  if (exportIdx === -1) return 'skip';
  const newSrc = src.slice(0, exportIdx) + headerBlock + src.slice(exportIdx);
  // Try to inject async headers() into the config object
  const withHeaders = newSrc.replace(
    /(?:module\.exports\s*=\s*|export\s+default\s+)(\{)/,
    (m, brace) => m.replace(brace, '{\n  async headers() {\n    return [{ source: "/(.*)", headers: securityHeaders }];\n  },\n')
  );
  fs.writeFileSync(cfgPath, withHeaders);
});

// ── 3. Add npm audit to package.json scripts ─────────────────────────────────
tryApply('Add npm audit to package.json scripts', () => {
  if (!fs.existsSync('package.json')) return 'skip';
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  if (!pkg.scripts) pkg.scripts = {};
  if (pkg.scripts['security:audit']) return 'skip';
  pkg.scripts['security:audit'] = 'npm audit --audit-level=high';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
});

// ── 4. Add .env.example if missing ───────────────────────────────────────────
tryApply('Create .env.example if missing', () => {
  if (fs.existsSync('.env.example') || fs.existsSync('.env.sample')) return 'skip';
  // Read .env and replace values with placeholders
  if (!fs.existsSync('.env')) return 'skip';
  const envContent = fs.readFileSync('.env', 'utf8');
  const exampleLines = envContent.split('\n').map(line => {
    if (!line.trim() || line.startsWith('#')) return line;
    const eq = line.indexOf('=');
    if (eq === -1) return line;
    const key = line.slice(0, eq);
    return key + '=your_' + key.toLowerCase() + '_here';
  });
  fs.writeFileSync('.env.example', exampleLines.join('\n'));
});

// ── 5. Add security section to README ────────────────────────────────────────
tryApply('Add security disclosure section to README', () => {
  const readmePath = ['README.md', 'README.MD', 'readme.md'].find(f => fs.existsSync(f));
  if (!readmePath) return 'skip';
  const src = fs.readFileSync(readmePath, 'utf8');
  if (/## Security|security policy|SECURITY\.md/i.test(src)) return 'skip';
  const section = \`
## Security

To report a security vulnerability, please email security@\${(() => {
  try { return JSON.parse(fs.readFileSync('package.json','utf8')).author?.email?.split('@')[1] || 'example.com'; } catch { return 'example.com'; }
})()} rather than opening a public issue. We aim to respond within 48 hours.

Scanned with [agentic-security](https://github.com/Clear-Capabilities/agentic-security).
\`;
  fs.appendFileSync(readmePath, section);
});

// ── 6. Create SECURITY.md if missing ─────────────────────────────────────────
tryApply('Create SECURITY.md', () => {
  if (fs.existsSync('SECURITY.md') || fs.existsSync('.github/SECURITY.md')) return 'skip';
  const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return {}; } })();
  const content = \`# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: \${pkg.author?.email || 'security@example.com'}
Response time: within 48 hours
Disclosure: coordinated, 90-day window

We appreciate responsible disclosure and will credit reporters in release notes.
\`;
  fs.writeFileSync('SECURITY.md', content);
});

// ── 7. Ensure .gitignore excludes common secret files ────────────────────────
tryApply('Protect common secret file patterns in .gitignore', () => {
  const gi = fs.existsSync('.gitignore') ? fs.readFileSync('.gitignore', 'utf8') : '';
  const patterns = ['*.pem', '*.key', '*.p12', '*.pfx', 'serviceAccountKey.json', '.gcp-credentials.json'];
  const missing = patterns.filter(p => !gi.includes(p));
  if (missing.length === 0) return 'skip';
  fs.appendFileSync('.gitignore', '\n# Secret file types — added by agentic-security /harden\n' + missing.join('\n') + '\n');
});

// Print results
console.log('');
console.log(W('Hardening Results', '1'));
console.log('');
if (applied.length) {
  console.log(W('Applied:', '32;1'));
  applied.forEach(a => console.log('  ' + W('✓', '32') + '  ' + a));
  console.log('');
}
if (skipped.length) {
  console.log(W('Skipped (already configured):', '2'));
  skipped.forEach(s => console.log('  –  ' + s));
  console.log('');
}
if (failed.length) {
  console.log(W('Failed:', '31'));
  failed.forEach(f => console.log('  ' + W('✗', '31') + '  ' + f));
  console.log('');
}
console.log(W('Next steps', '1'));
console.log('  Review applied changes: git diff');
console.log('  Run /scan --all to check remaining findings');
console.log('  Run /launch-check before shipping');
console.log('');
"
```

Review the changes with `git diff` before committing — `/harden` modifies real files. If any change doesn't match your project's conventions, revert that file with `git checkout <file>`.
