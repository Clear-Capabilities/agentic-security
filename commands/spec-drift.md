---
description: Specification-drift detector — functions whose names claim a behavior the body doesn't deliver. Catches `validateOwnership()` that doesn't check user identity, `sanitize()` that doesn't escape, `verifySignature()` that doesn't verify.
argument-hint: "[path]"
---

Run the scanner with the v3 specification-mining detector and show only `family: 'spec-drift'` findings.

```bash
PATH_ARG="."
for arg in "$@"; do
  [ "${arg:0:1}" != "-" ] && PATH_ARG="$arg"
done

mkdir -p .agentic-security
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json --output .agentic-security/_spec-drift.json >/dev/null 2>&1 || true

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/_spec-drift.json','utf8')); }
catch { console.log('Scanner did not run.'); process.exit(0); }
const items = (scan.findings || []).filter(f => f.family === 'spec-drift');
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33', RED='31';

console.log('');
console.log(W('Specification-drift findings: ' + items.length, BOLD));
console.log(W('  Catches functions whose NAMES claim a behavior the BODY does not deliver.', DIM));
console.log(W('  Low confidence by default — review each as you would any spec mismatch.', DIM));
console.log('');

const byKind = new Map();
for (const f of items) {
  const kind = f.specMined && f.specMined.family ? f.specMined.family : 'other';
  if (!byKind.has(kind)) byKind.set(kind, []);
  byKind.get(kind).push(f);
}

for (const [kind, list] of byKind) {
  console.log(W(kind + ' (' + list.length + ')', BOLD));
  for (const f of list.slice(0, 12)) {
    const color = f.severity === 'high' ? RED : YELLOW;
    console.log('  [' + W((f.severity||'').toUpperCase(), color) + '] ' + (f.vuln||'').slice(0, 80));
    console.log('    ' + W(f.file + ':' + f.line, DIM));
    if (f.description) console.log('    ' + W('why: ' + f.description, DIM));
  }
  console.log('');
}

if (!items.length) console.log(W('  ✅  No spec-drift findings.', '32'));
"
rm -f .agentic-security/_spec-drift.json
```

## What it catches

| Function name pattern | Body must reference | If missing |
|---|---|---|
| `validateOwnership` / `checkOwner` | `req.user`, `userId`, `owner_id` | high — CWE-639 |
| `validateAccess` / `authorize` / `canAccess` | `role`, `permission`, `scope`, `claim` | high — CWE-863 |
| `sanitize*` / `escape*` / `purify*` | `DOMPurify`, `escape`, `bleach`, `replace` | high — CWE-79 |
| `verifySignature` / `checkSig` | `hmac`, `verify`, `timingSafeEqual` | high — CWE-347 |
| `verifyWebhook` | `stripeSignature`, `webhook_secret`, `svix` | high — CWE-345 |
| `rateLimit` / `throttle` | rate-limit lib or windowing primitive | medium — CWE-770 |
| `isAdmin` / `requireAdmin` | admin-role reference | high — CWE-862 |
| `requireAuth` / `mustBeLoggedIn` | session/user lookup | medium — CWE-306 |

## Tuning

Spec-drift is noisy on legacy codebases where naming has lied for years. Two ways to tune:
1. **Project-level allowlist**: add a `.agentic-security/rules.yml` suppression by `family: spec-drift` and `files: ["legacy/**"]`.
2. **Active learning**: `/triage` a wave of FPs and the engine learns to demote the matching pattern.

🛡  agentic-security · created by ClearCapabilities.Com
