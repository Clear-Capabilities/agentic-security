---
description: Workflow installers + on-write guards. Hooks, CI, pre-deploy gate, bodyguard, destructive-guard, model-cost optimizer
argument-hint: "[--hooks|--ci|--predeploy|--bodyguard|--destructive-guard|--model-optimizer] [--provider github|gitlab|circleci|buildkite|jenkins] [--fail-on critical|high|medium] [--apply]"
---

# /setup

Workflow + guard installer dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--hooks` | Install pre-commit security hook tuned to your project's stack (husky / pre-commit / lefthook / native). `--severity critical|high|medium`, `--diff-only|--full`, `--manager auto|husky|pre-commit|lefthook|native` |
| `--ci` | Generate a CI security-gate workflow. Auto-detects your provider or set `--provider github|gitlab|circleci|buildkite|jenkins`; `--fail-on critical|high|medium`; dry-run unless `--apply`. GitHub Actions is generated inline; gitlab/circleci/buildkite/jenkins come from `scripts/ci-templates/` |
| `--predeploy` | Pre-deploy gate that blocks `vercel`/`fly`/`wrangler` deploys **in your terminal** (not just CI) on critical/KEV findings. Sub-commands: `install` (default), `check`, `status`, `off` |
| `--bodyguard` | Configure the AI bodyguard PreToolUse hook. Modes: `warn`, `block`, `off`. Per-project forbidden APIs at `.agentic-security/forbidden-apis.yml` |
| `--destructive-guard` | Configure the destructive-Bash-command guard (rm -rf, force-push, etc.). Modes: `warn`, `block`, `off` |
| `--model-optimizer` | Enable the per-prompt model-cost advisor (suggests a cheaper model + depth with est. token savings; advisory only by default — it can't switch for you). Modes: `advise`, `off`. `--quality <0-10>` sets the cost-quality dial (default `7`: `0`=never downgrade, `10`=cheapest); `--min-savings <usd>` is the absolute anti-noise floor; `--interactive` opts into a real `AskUserQuestion` choice (keep defaults / show the `/model` command / apply the cheaper model to delegated sub-agent work this session) instead of a read-only tip — costs a little context on the prompts where it fires, off by default. See `docs/MODEL_COST_OPTIMIZATION.md` |
| `--all` | One-pass setup: installs hooks + CI + bodyguard + destructive-guard with sensible defaults (model-optimizer + pre-deploy gate stay opt-in) |

Bare `/setup` (no flag) prints this mode menu.

## `--all` (one-pass setup)

Runs the four installers in sequence with safe defaults, pausing for confirmation before anything that writes outside `.agentic-security/`:

1. `--hooks` — auto-detected manager, `--severity high`.
2. `--ci` — auto-detected provider (github/gitlab/circleci/buildkite/jenkins), `--fail-on high`.
3. `--bodyguard` — `mode=warn` (non-blocking until the user opts into `block`).
4. `--destructive-guard` — `mode=warn`.

Two modes stay **out** of `--all` and remain opt-in: the model-cost optimizer (`--model-optimizer`, it emits per-prompt suggestions) and the pre-deploy gate (`--predeploy`, it edits your shell profile to intercept deploy commands). Mention both once in the summary so the user knows they exist.

Prints a single summary of what was installed and the one command to harden each further.

## Examples

```bash
/setup                                           # show the mode menu
/setup --all                                     # hooks + CI + both guards, defaults
/setup --hooks --severity critical               # husky/pre-commit hook
/setup --ci --provider github --apply            # write GitHub Actions workflow
/setup --ci --provider gitlab --apply            # write .gitlab-ci.yml from template
/setup --ci --provider buildkite                 # preview Buildkite pipeline (dry-run)
/setup --ci --fail-on critical --apply           # GitHub Actions, block on critical
/setup --predeploy                               # install the pre-deploy gate config
/setup --predeploy check                         # run the gate against the last scan now
/setup --predeploy off                           # disable the gate
/setup --bodyguard mode=block                     # block insecure edits
/setup --destructive-guard mode=warn             # warn on destructive bash
/setup --model-optimizer                         # enable cheaper-model tips (advise)
/setup --model-optimizer --quality 9             # lean aggressive on cost (dial 9/10)
/setup --model-optimizer --min-savings 0.05      # absolute floor: only ≥ $0.05
/setup --model-optimizer --interactive           # let me choose via AskUserQuestion, not just read a tip
/setup --model-optimizer mode=off                # disable
```

## Implementation

The routing modes call their installers directly:

- `--hooks` → `posture/workflow-installer.js` (detectProject, buildHookConfig) + the pre-commit hook writer (husky / pre-commit / lefthook / native).
- `--bodyguard` / `--destructive-guard` → the existing PreToolUse hooks.
- `--model-optimizer` → config write only (see below).

`--ci` and `--predeploy` run the inline generators below.

`--model-optimizer` writes `.agentic-security/model-optimizer.json`:

```json
{ "mode": "advise", "costQualityTradeoff": 7, "minSavingsUsd": 0.01, "assumedModel": "claude-opus-4-8", "assumedCachedTokens": null, "interactive": false }
```

Set `mode` from the flag (`advise` default, or `off`), `costQualityTradeoff` from `--quality` (0–10, default 7), `minSavingsUsd` from `--min-savings`, and `interactive` to `true` when `--interactive` is passed (default `false`). The advisor (`hooks/model-cost-advisor.js`, UserPromptSubmit) and model capture (`hooks/session-start-model-capture.js`, SessionStart) are already registered in `hooks/hooks.json`, so enabling is purely the config write — no hook installation step. Confirm the config landed (`mode` is `advise`), then point the user at `docs/MODEL_COST_OPTIMIZATION.md`. If `--interactive` was passed, mention explicitly that qualifying prompts will now cost a little extra context (unlike the default tip-only mode) in exchange for a real choice.

### `--ci` — multi-provider CI security gate

Detects the CI provider (or honours `--provider`), prints the workflow as a dry-run, and writes it only on `--apply`. GitHub Actions is generated inline; gitlab / circleci / buildkite / jenkins are emitted from `scripts/ci-templates/`. Threshold comes from `--fail-on` (or a bare `critical|high|medium`), default `high`.

```bash
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const args = process.argv.slice(1);
const _foIdx = args.indexOf('--fail-on');
const severity = (args.find(a => a.startsWith('--fail-on=')) || '').split('=')[1]
              || (_foIdx >= 0 ? args[_foIdx + 1] : null)
              || args.find(a => /^(critical|high|medium)$/.test(a))
              || 'high';
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
```

### `--predeploy` — pre-deploy gate

Wraps `vercel` / `fly` / `wrangler` so a deploy is blocked on critical/KEV findings — in your terminal, not just CI. The sub-command is read from `$2`: `install` (default), `check`, `status`, `off`.

```bash
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
```

### After generating a CI workflow

Before declaring done, validate the generated workflow so a broken file never lands:

1. **Lint the YAML** — parse it (the generator emits valid YAML; if a parser is available, confirm it loads and that the security-gate job and `fail-on` threshold are present).
2. **Offer a PR** — when `--apply` wrote files and the repo has a remote, offer to open a PR (`agentic-security/ci-gate` branch) with the workflow + a one-paragraph body explaining the gate and its threshold, rather than committing straight to the working branch.
