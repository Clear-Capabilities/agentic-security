---
description: Guide for rotating a leaked secret — detects the provider from the key format, lists every file that references it, and gives platform-specific rotation steps. Add --scrub-history to also rewrite git history with git filter-repo / BFG.
argument-hint: "[secret-value-or-finding-id] [--scrub-history]"
---

Rotate a leaked secret. Detects which provider the secret belongs to (Stripe, OpenAI, Anthropic, GitHub, Supabase, etc.), finds every file that references it, and gives exact rotation steps for your deployment platform.

```bash
node -e "
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const arg = (process.argv[1] || '').trim();

// Load last scan for leaked secret findings
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

// Identify provider from key prefix / pattern
function detectProvider(value) {
  if (!value) return null;
  if (/^sk-[a-zA-Z0-9]{20,}/.test(value)) return 'OpenAI';
  if (/^sk-ant-[a-zA-Z0-9\-_]{20,}/.test(value)) return 'Anthropic';
  if (/^sk_(live|test)_[a-zA-Z0-9]{20,}/.test(value)) return 'Stripe';
  if (/^rk_(live|test)_[a-zA-Z0-9]{20,}/.test(value)) return 'Stripe Restricted Key';
  if (/^whsec_[a-zA-Z0-9]{20,}/.test(value)) return 'Stripe Webhook';
  if (/^ghp_[a-zA-Z0-9]{36}/.test(value)) return 'GitHub Personal Access Token';
  if (/^github_pat_/.test(value)) return 'GitHub Fine-Grained PAT';
  if (/^eyJh/.test(value) && value.split('.').length === 3) return 'JWT (check provider)';
  if (/^AIza[0-9A-Za-z\-_]{35}/.test(value)) return 'Google API Key';
  if (/^ya29\./.test(value)) return 'Google OAuth Token';
  if (/^AKIA[0-9A-Z]{16}$/.test(value)) return 'AWS Access Key';
  if (/^xoxb-/.test(value)) return 'Slack Bot Token';
  if (/^xoxp-/.test(value)) return 'Slack User Token';
  if (/^SG\./.test(value)) return 'SendGrid API Key';
  if (/^AC[a-zA-Z0-9]{32}/.test(value)) return 'Twilio Account SID';
  if (/^re_[a-zA-Z0-9]{20,}/.test(value)) return 'Resend API Key';
  return 'Unknown';
}

const ROTATION_GUIDES = {
  'OpenAI': [
    '1. Go to platform.openai.com → API keys → Delete the compromised key',
    '2. Create a new key: platform.openai.com/api-keys',
    '3. Update OPENAI_API_KEY in your platform env vars (Vercel/Railway/Render/Fly)',
    '4. Do NOT commit the new key — set it as an environment variable only',
  ],
  'Anthropic': [
    '1. Go to console.anthropic.com → API Keys → Deactivate the compromised key',
    '2. Create a new key in the Anthropic Console',
    '3. Update ANTHROPIC_API_KEY in your platform env vars',
  ],
  'Stripe': [
    '1. Go to dashboard.stripe.com → Developers → API Keys → Roll the compromised key',
    '2. Stripe issues a new key immediately — the old one stops working within hours',
    '3. Update STRIPE_SECRET_KEY in your platform env vars',
    '4. If a webhook secret (whsec_) was leaked, regenerate the webhook endpoint signing secret',
  ],
  'GitHub Personal Access Token': [
    '1. Go to github.com/settings/tokens → Delete the compromised token',
    '2. Create a replacement with minimum required scopes',
    '3. Update the token in your CI/CD secrets or env vars',
  ],
  'AWS Access Key': [
    '1. Go to AWS Console → IAM → Users → Security credentials → Deactivate key',
    '2. Check CloudTrail for unauthorized API calls made with this key',
    '3. Create a new access key with minimum required permissions',
    '4. Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your env vars',
    '5. Consider using IAM roles instead of long-lived access keys',
  ],
  'Supabase': [
    '1. Go to app.supabase.com → Project Settings → API → Rotate the service_role key',
    '2. Update SUPABASE_SERVICE_ROLE_KEY in your platform env vars',
    '3. Audit RLS policies — a leaked service key bypasses all RLS',
  ],
};

// Collect secret findings from scan
const secretFindings = scan ? (scan.findings || []).filter(f =>
  f.severity === 'critical' &&
  /secret|credential|api.?key|token|password/i.test(f.vuln || f.title || '')
) : [];

console.log('');
console.log(W('Secret Rotation Guide', '1'));
console.log('');

// If a specific secret or finding ID was provided
if (arg) {
  const provider = detectProvider(arg);
  if (provider !== 'Unknown' && provider !== null) {
    console.log(W('Provider detected: ' + provider, '36;1'));
    console.log('');
    const guide = ROTATION_GUIDES[provider];
    if (guide) {
      console.log(W('Rotation steps:', '1'));
      guide.forEach(step => console.log('  ' + step));
      console.log('');
    }
  }
}

// Find all files referencing leaked secrets
if (secretFindings.length > 0) {
  console.log(W('Leaked secrets found in scan:', '31;1'));
  console.log('');
  for (const f of secretFindings.slice(0, 10)) {
    const provider = f.title ? detectProvider('') : 'Unknown';
    console.log('  ' + W('●', '31') + '  ' + (f.title || f.vuln));
    console.log('     ' + f.file + (f.line ? ':' + f.line : ''));
    if (ROTATION_GUIDES[provider]) {
      console.log('     Provider: ' + provider + ' → see rotation steps above');
    }
    console.log('');
  }
}

// Detect platform and give env var update instructions
console.log(W('Update env vars on your platform:', '1'));
console.log('');

const hasVercel = fs.existsSync('vercel.json') || fs.existsSync('.vercel');
const hasRailway = fs.existsSync('railway.json') || fs.existsSync('railway.toml');
const hasFly = fs.existsSync('fly.toml');
const hasRender = fs.existsSync('render.yaml');
const hasNetlify = fs.existsSync('netlify.toml');

if (hasVercel) console.log('  Vercel:   vercel env add SECRET_NAME production');
if (hasRailway) console.log('  Railway:  railway variables set SECRET_NAME=new_value');
if (hasFly) console.log('  Fly.io:   fly secrets set SECRET_NAME=new_value');
if (hasRender) console.log('  Render:   Dashboard → Environment → Update variable');
if (hasNetlify) console.log('  Netlify:  netlify env:set SECRET_NAME new_value');
if (!hasVercel && !hasRailway && !hasFly && !hasRender && !hasNetlify) {
  console.log('  Export to your environment (Vercel, Railway, Fly, Render, Netlify dashboard)');
}

console.log('');
console.log(W('After rotating:', '1'));
console.log('  1. Verify the old key no longer works (test an API call)');
console.log('  2. Check git history: git log --all -p | grep -i <partial_key>');
console.log('  3. If leaked key was in git history, contact GitHub support to purge cached views');
console.log('  4. Monitor for unauthorized usage in your provider dashboard for 24h');
console.log('');
" -- "$1"
```

A leaked secret that is still in git history is still compromised even after rotation, because anyone who cloned the repo before the rotation has the old key. If the key was committed, assume it was used — check provider audit logs immediately.

## `--scrub-history` — purge from git history

Pass `--scrub-history` along with the leaked value to also rewrite the value out of every past commit using `git filter-repo` (preferred) or BFG. The command will:

1. Refuse if the working tree is dirty (uncommitted changes would be lost).
2. Refuse if the repo has unmerged feature branches (rewriting history orphans them) — pass `--force` to override.
3. Detect which tool is available and print install instructions if neither is (`brew install git-filter-repo` or `brew install bfg`).
4. Create a backup ref (`backup/pre-scrub-<timestamp>`) so the rewrite is reversible until you `git push --force`.
5. Replace every occurrence of the value with `***REVOKED***` across all commits, branches, and tags.
6. Write an audit log to `.agentic-security/rotation-history/<timestamp>.json` (pre-/post-rewrite SHAs, scrubbed value prefix, timestamp, operator).
7. Print the irreversible next steps: `git push --force`, force-update protected branches in your hoster's UI, notify collaborators to re-clone, and (GitHub only) open a support ticket to purge cached blob views.

**Even with history scrubbed, treat the original key as compromised.** Anyone with a pre-rewrite clone or a cached GitHub blob view still has it. Rotating the value at the provider is the only thing that actually removes danger — history scrub is hygiene for audits and embarrassment, not safety.
