---
description: CI/deploy security gates — CI workflow, pre-deploy gate, git hooks. Default generates a CI workflow.
argument-hint: "[--provider github|gitlab|circleci|buildkite|jenkins] [--predeploy install|check|status|off] [--hooks [--threshold critical|high|medium] [--uninstall]] [--apply] [--comment]"
---

Three modes behind one command:

- `/ci` (default) — Generate a CI security gate workflow
- `/ci --predeploy` — Pre-deploy gate wrapping vercel/fly/wrangler
- `/ci --hooks` — Install pre-commit + pre-push git hooks

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true

MODE="ci"
for arg in "$@"; do
  case "$arg" in
    --predeploy) MODE="predeploy" ;;
    --hooks) MODE="hooks" ;;
  esac
done

case "$MODE" in

# ── CI gate (default) ──
ci)
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const args = process.argv.slice(1);
const severity = args.find(a => /^(critical|high|medium)$/.test(a)) || 'high';
const shouldApply = args.includes('--apply');
const addComment = args.includes('--comment');

const providerExplicit = (args.find(a => a.startsWith('--provider=')) || '').split('=')[1]
                       || (args.indexOf('--provider') >= 0 ? args[args.indexOf('--provider') + 1] : null);
const detected = providerExplicit
  || (fs.existsSync('.gitlab-ci.yml') ? 'gitlab' : null)
  || (fs.existsSync('.circleci/config.yml') ? 'circleci' : null)
  || (fs.existsSync('.buildkite/pipeline.yml') ? 'buildkite' : null)
  || (fs.existsSync('Jenkinsfile') ? 'jenkins' : null)
  || 'github';

if (detected !== 'github') {
  const ROOT = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));
  const TEMPLATES = {
    gitlab:   { src: path.join(ROOT, 'scripts/ci-templates/.gitlab-ci.yml'),       dest: '.gitlab-ci.yml' },
    circleci: { src: path.join(ROOT, 'scripts/ci-templates/.circleci-config.yml'), dest: '.circleci/config.yml' },
    buildkite:{ src: path.join(ROOT, 'scripts/ci-templates/buildkite.yml'),         dest: '.buildkite/pipeline.yml' },
    jenkins:  { src: path.join(ROOT, 'scripts/ci-templates/Jenkinsfile'),           dest: 'Jenkinsfile' },
  };
  const t = TEMPLATES[detected];
  if (!t) { console.error('Unknown provider: ' + detected); process.exit(2); }
  const content = fs.readFileSync(t.src, 'utf8');
  console.log('');
  console.log(W('Detected provider: ' + detected, '1'));
  console.log('Target file:  ' + t.dest);
  console.log('');
  if (shouldApply && !fs.existsSync(t.dest)) {
    fs.mkdirSync(path.dirname(t.dest), { recursive: true });
    fs.writeFileSync(t.dest, content);
    console.log(W('  ✓  Wrote ' + t.dest, '32'));
    process.exit(0);
  }
  console.log(content.split('\\n').map(l => '  ' + l).join('\\n'));
  console.log('');
  console.log(W('  Pass --apply to write the file.', '33'));
  process.exit(0);
}

const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const isNode = !!pkg;
const nodeVersion = pkg?.engines?.node?.replace(/[^0-9.]/g,'').split('.')[0] || '24';
const installCmd = isNode ? 'npm ci' : 'echo no install';
const wfPath = '.github/workflows/security.yml';
const exists = fs.existsSync(wfPath);

const yaml = \`name: Security Scan

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  security:
    name: agentic-security scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '\${nodeVersion}'

      - name: Install dependencies
        run: \${installCmd}

      - name: Run security scan
        id: scan
        run: |
          npx --yes agentic-security scan . \\\\
            --format sarif --output security-results.sarif \\\\
            --format json --output security-results.json \\\\
            --no-network \\\\
          || true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
        continue-on-error: true

      - name: Fail on \${severity}+ findings
        run: |
          node -e "
            const r=JSON.parse(require('fs').readFileSync('security-results.json','utf8'));
            const S={critical:0,high:1,medium:2};
            const bad=(r.findings||[]).filter(f=>(S[f.severity]??9)<=(S['\${severity}']??1));
            if(bad.length){console.error(bad.length+' \${severity}+ finding(s)');process.exit(1);}
            console.log('Security gate passed.');
          "
\`;

console.log('');
console.log(W('GitHub Actions Security Gate', '1'));
console.log('  Blocks on: ' + severity + '+   File: ' + wfPath);
console.log('');
if (shouldApply) {
  if (exists) { console.log(W('  ⚠  ' + wfPath + ' already exists. Delete it first.', '33')); }
  else { fs.mkdirSync('.github/workflows',{recursive:true}); fs.writeFileSync(wfPath,yaml); console.log(W('  ✓  Created ' + wfPath, '32')); }
} else {
  console.log(W('  DRY RUN — pass --apply to write.', '33'));
  console.log('');
  console.log(yaml.split('\\n').map(l => '  ' + l).join('\\n'));
}
console.log('');
" -- "$@"
  ;;

# ── Pre-deploy gate ──
predeploy)
  echo ""
  echo "Pre-deploy gate — blocks vercel/fly/wrangler deploys on critical findings."
  echo ""
  echo "This gate intercepts deploy commands in your terminal (not just CI)."
  echo ""
  echo "Install: add to ~/.zshrc or ~/.bashrc:"
  echo "  source ${CLAUDE_PLUGIN_ROOT}/scripts/predeploy-gate.sh"
  echo ""
  echo "Config: .agentic-security/predeploy-gate.json"
  echo '  { "block_on": ["critical"], "block_on_kev": true, "require_recent_scan_hours": 24 }'
  echo ""

  SUB="${2:-install}"
  case "$SUB" in
    install)
      mkdir -p .agentic-security
      if [ ! -f .agentic-security/predeploy-gate.json ]; then
        echo '{ "block_on": ["critical"], "block_on_kev": true, "require_recent_scan_hours": 24 }' > .agentic-security/predeploy-gate.json
        echo "  ✓  Wrote .agentic-security/predeploy-gate.json"
      fi
      echo ""
      echo "  Add to your shell profile:"
      echo "    source ${CLAUDE_PLUGIN_ROOT}/scripts/predeploy-gate.sh"
      ;;
    check)
      bash ${CLAUDE_PLUGIN_ROOT}/scripts/predeploy-gate.sh check
      ;;
    status)
      echo "  Config:"
      cat .agentic-security/predeploy-gate.json 2>/dev/null || echo "  (not configured)"
      echo ""
      echo "  Last scan:"
      node -e "try{const s=JSON.parse(require('fs').readFileSync('.agentic-security/last-scan.json','utf8'));console.log('  '+s.scannedAt+' — '+(s.findings||[]).length+' findings');}catch{console.log('  (no scan)')}" 2>/dev/null
      ;;
    off)
      echo '{ "block_on": [], "block_on_kev": false }' > .agentic-security/predeploy-gate.json
      echo "  ✓  Pre-deploy gate disabled."
      ;;
  esac
  ;;

# ── Git hooks ──
hooks)
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const args = process.argv.slice(1);
const uninstall = args.includes('--uninstall');
const ti = args.indexOf('--threshold');
const threshold = ti >= 0 ? args[ti+1] : 'critical';

if (!fs.existsSync('.git')) { console.error('Not a git repo.'); process.exit(1); }
const HOOK_DIR = '.git/hooks';
fs.mkdirSync(HOOK_DIR, { recursive: true });
const MARKER = '# agentic-security:managed';

if (uninstall) {
  for (const name of ['pre-commit', 'pre-push']) {
    const p = path.join(HOOK_DIR, name);
    if (!fs.existsSync(p)) continue;
    if (!fs.readFileSync(p, 'utf8').includes(MARKER)) { console.log(W('  ⚠  ' + name + ' not installed by us.', '33')); continue; }
    fs.unlinkSync(p);
    console.log(W('  ✓  Removed ' + p, '32'));
  }
  process.exit(0);
}

const preCommit = \`#!/usr/bin/env bash
\${MARKER}
set -e
STAGED=\\$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\\\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|java|kt|go|cs|sol|tf|yaml|yml|json)\\$' || true)
if [ -z \\"\\$STAGED\\" ]; then exit 0; fi
echo \\"agentic-security: scanning \\$(echo \\\\\\"\\$STAGED\\\\\\" | wc -l) staged files...\\"
TMP=\\$(mktemp -d); trap 'rm -rf \\\\\\"\\$TMP\\\\\\"' EXIT
for f in \\$STAGED; do mkdir -p \\"\\$TMP/\\$(dirname \\\\\\"\\$f\\\\\\")\\" ; git show :\\\\\\"\\$f\\\\\\" > \\"\\$TMP/\\$f\\" 2>/dev/null || true; done
npx --yes agentic-security scan \\"\\$TMP\\" --threshold \${threshold} --json > /tmp/agentic-security-precommit.json 2>/dev/null || true
node -e \\"const f=require('fs');let r;try{r=JSON.parse(f.readFileSync('/tmp/agentic-security-precommit.json','utf8'));}catch{process.exit(0);} const S={critical:0,high:1,medium:2,low:3}; const bad=(r.findings||[]).filter(x=>(S[x.severity]??9)<=(S['\${threshold}']??0)); if(bad.length){console.error('BLOCKED — '+bad.length+' \${threshold}+ finding(s)');bad.slice(0,5).forEach(x=>console.error('  ['+x.severity+'] '+x.vuln+' — '+x.file+':'+x.line));process.exit(1);}\\"
\`;

const prePush = \`#!/usr/bin/env bash
\${MARKER}
set -e
UPSTREAM=\\$(git rev-parse --abbrev-ref @{u} 2>/dev/null || echo main)
echo \\"agentic-security: diff scan against \\$UPSTREAM ...\\"
npx --yes agentic-security scan . --changed-since \\\\\\"\\$UPSTREAM\\\\\\" --threshold \${threshold} --json > /tmp/agentic-security-prepush.json 2>/dev/null || true
node -e \\"const f=require('fs');let r;try{r=JSON.parse(f.readFileSync('/tmp/agentic-security-prepush.json','utf8'));}catch{process.exit(0);} const S={critical:0,high:1,medium:2,low:3}; const bad=(r.findings||[]).filter(x=>(S[x.severity]??9)<=(S['\${threshold}']??0)); if(bad.length){console.error('BLOCKED — '+bad.length+' \${threshold}+ finding(s)');process.exit(1);}\\"
\`;

for (const [name, body] of [['pre-commit', preCommit], ['pre-push', prePush]]) {
  const p = path.join(HOOK_DIR, name);
  if (fs.existsSync(p) && !fs.readFileSync(p, 'utf8').includes(MARKER)) {
    console.log(W('  ⚠  ' + p + ' already exists and not managed by us.', '33'));
    continue;
  }
  fs.writeFileSync(p, body);
  fs.chmodSync(p, 0o755);
  console.log(W('  ✓  Installed ' + p, '32'));
}
console.log('');
console.log(W('  Threshold: ' + threshold + '   Uninstall: /ci --hooks --uninstall', '2'));
" -- "$@"
  ;;
esac
```

## Quick reference

| Mode | Purpose |
|---|---|
| `/ci` | CI workflow (GitHub default, `--provider` for others) |
| `/ci --predeploy` | Block vercel/fly/wrangler deploys |
| `/ci --hooks` | Pre-commit + pre-push git hooks |

Pass `--apply` to write files. Default is dry-run.
