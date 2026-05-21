---
description: Generate a CI security gate that fails the build on critical/high findings. --provider for non-GitHub CI.
argument-hint: "[--provider github|gitlab|circleci|buildkite|jenkins] [--apply]"
---

Generate a CI security gate that fails the build on critical/high findings.

Default (no `--provider`): writes `.github/workflows/security.yml` for GitHub Actions.

With `--provider gitlab|circleci|buildkite|jenkins`: writes the matching template from `scripts/ci-templates/`. Auto-detects the provider when the file shape is unambiguous (`.gitlab-ci.yml` present, etc.); pass `--provider` to override.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const args = process.argv.slice(1);
const severity = args.find(a => /^(critical|high|medium)$/.test(a)) || 'high';
const shouldApply = args.includes('--apply');
const addComment = args.includes('--comment');

// Provider dispatch (merged from former /ci-gate-multi).
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
    gitlab:   { src: path.join(ROOT, 'scripts/ci-templates/.gitlab-ci.yml'),       dest: '.gitlab-ci.yml',           merge: 'extend existing or include via local:' },
    circleci: { src: path.join(ROOT, 'scripts/ci-templates/.circleci-config.yml'), dest: '.circleci/config.yml',     merge: 'merge into existing workflows section' },
    buildkite:{ src: path.join(ROOT, 'scripts/ci-templates/buildkite.yml'),         dest: '.buildkite/pipeline.yml',  merge: 'append to steps:' },
    jenkins:  { src: path.join(ROOT, 'scripts/ci-templates/Jenkinsfile'),           dest: 'Jenkinsfile',              merge: 'merge stages: into existing pipeline' },
  };
  const t = TEMPLATES[detected];
  if (!t) {
    console.error('Unknown provider: ' + detected + '. Try: github | gitlab | circleci | buildkite | jenkins');
    process.exit(2);
  }
  const content = fs.readFileSync(t.src, 'utf8');
  console.log('');
  console.log(W('Detected provider: ' + detected, '1'));
  console.log('Target file:  ' + t.dest);
  console.log('');
  if (shouldApply) {
    if (fs.existsSync(t.dest)) {
      console.log(W('  ⚠  ' + t.dest + ' already exists.', '33'));
      console.log('  ' + t.merge);
      console.log('');
      console.log('  Template content (copy the relevant block):');
    } else {
      fs.mkdirSync(path.dirname(t.dest), { recursive: true });
      fs.writeFileSync(t.dest, content);
      console.log(W('  ✓  Wrote ' + t.dest, '32'));
      process.exit(0);
    }
  }
  console.log(content.split('\\n').map(l => '  ' + l).join('\\n'));
  console.log('');
  console.log(W('  Pass --apply to write the file (or its template, when one already exists).', '33'));
  process.exit(0);
}

// GitHub Actions path (default, preserved from the original /ci-gate body).

// Detect project type
const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const isNode = !!pkg;
const nodeVersion = pkg?.engines?.node?.replace(/[^0-9.]/g,'').split('.')[0] || '24';
const hasPython = fs.existsSync('requirements.txt') || fs.existsSync('pyproject.toml');
const installCmd = isNode ? 'npm ci' : hasPython ? 'pip install -r requirements.txt' : 'echo no install';
const testCmd = isNode ? (pkg?.scripts?.test ? 'npm test' : 'echo no tests') : hasPython ? 'pytest' : 'echo no tests';

// Check if workflow already exists
const wfPath = '.github/workflows/security.yml';
const exists = fs.existsSync(wfPath);

const pluginVersion = '0.31.1';

const yaml = \`name: Security Scan

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write  # needed for PR comments
  security-events: write  # needed for SARIF upload

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
          cache: '\${isNode ? 'npm' : 'none'}'

      - name: Install dependencies
        run: \${installCmd}

      - name: Install agentic-security scanner
        run: |
          npm install -g @clear-capabilities/agentic-security-scanner@\${pluginVersion} 2>/dev/null || \\
          npx --yes @clear-capabilities/agentic-security-scanner@\${pluginVersion} --version || \\
          echo 'Scanner install attempted'

      - name: Run security scan
        id: scan
        run: |
          node scanner/dist/agentic-security.mjs scan . \\
            --format sarif \\
            --output security-results.sarif \\
            --format json \\
            --output security-results.json \\
            --no-network \\
          || true

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
        continue-on-error: true

\${addComment ? \`      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let body = '## 🛡 Security Scan Results\\n';
            try {
              const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));
              const findings = results.findings || [];
              const crit = findings.filter(f => f.severity === 'critical').length;
              const high = findings.filter(f => f.severity === 'high').length;
              const grade = crit > 0 ? 'F' : high > 2 ? 'D' : high > 0 ? 'C' : 'B';
              body += \\\`Grade: **\\\${grade}** | Critical: \\\${crit} | High: \\\${high} | Total: \\\${findings.length}\\\\n\\\\n\\\`;
              if (crit > 0 || high > 0) {
                body += '### Findings requiring attention\\n';
                findings.filter(f => f.severity === 'critical' || f.severity === 'high')
                  .slice(0, 10)
                  .forEach(f => { body += \\\`- [\\\${f.severity.toUpperCase()}] \\\${f.vuln || f.title} — \\\${f.file}:\\\${f.line}\\\\n\\\`; });
              } else {
                body += '✅ No critical or high findings.';
              }
            } catch { body += 'Scan results unavailable.'; }
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body,
            });
\` : ''}
      - name: Fail on \${severity}+ findings
        run: |
          node -e "
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));
            const findings = results.findings || [];
            const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            const threshold = sevOrder['\${severity}'] ?? 1;
            const blocking = findings.filter(f => (sevOrder[f.severity] ?? 99) <= threshold);
            if (blocking.length > 0) {
              console.error('Security gate failed: ' + blocking.length + ' \${severity}+ finding(s)');
              blocking.slice(0, 5).forEach(f => console.error('  [' + f.severity + '] ' + (f.vuln || f.title) + ' — ' + f.file + ':' + f.line));
              process.exit(1);
            }
            console.log('Security gate passed.');
          "
\`;

console.log('');
console.log(W('GitHub Actions Security Gate', '1'));
console.log('  Blocks on: ' + severity + ' and above');
console.log('  PR comments: ' + (addComment ? 'enabled' : 'disabled (add --comment to enable)'));
console.log('  File: ' + wfPath);
console.log('');

if (shouldApply) {
  if (exists) {
    console.log(W('  ⚠  ' + wfPath + ' already exists. Skipping to avoid overwrite.', '33'));
    console.log('  Delete it first or review and merge manually.');
  } else {
    fs.mkdirSync('.github/workflows', { recursive: true });
    fs.writeFileSync(wfPath, yaml);
    console.log(W('  ✓  Created ' + wfPath, '32'));
  }
} else {
  console.log(W('  DRY RUN — pass --apply to write the file.', '33'));
  console.log('');
  console.log('  Generated workflow:');
  console.log('');
  console.log(yaml.split('\n').map(l => '  ' + l).join('\n'));
}
console.log('');
" -- "$@"
```

Pass `--apply` to write the file, `--comment` to enable PR review comments, and `--severity critical|high|medium` to set the failure threshold. Default threshold is `high` — critical+high findings fail the build.

After applying: `git add .github/workflows/security.yml && git commit -m "ci: add security gate"`.
