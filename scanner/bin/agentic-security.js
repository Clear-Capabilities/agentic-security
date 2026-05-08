#!/usr/bin/env node
// agentic-security CLI — scan, fix, baseline, version.
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { toJSON, toMarkdown, toSARIF, toCLI, toHTML, exitCodeFor, normalizeFindings } from '../src/report/index.js';

const USAGE = `agentic-security <command> [options]

Commands:
  scan [path]                  Full SAST + SCA + Secrets sweep (default: cwd)
  fix --finding <id> [--apply] Apply fix for a single finding
  baseline save|diff [path]    Manage finding baselines
  setup [project-dir]          Install /security-* shortcut commands into a project
  version                      Print version

Options:
  --only sast|sca|secrets      Limit scan to one pillar
  --format json|md|sarif|cli|html  Report format (default: cli)
  --no-network                 Skip OSV/registry queries (offline mode)
  --verbose                    Include fix bodies in CLI output
  --output <file>              Write report to file instead of stdout

Exit codes:
  0 = clean   1 = low/medium   2 = high   3 = critical   4 = error`;

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2);
      if (v !== undefined) { args.flags[k] = v; continue; }
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { args.flags[k] = next; i++; }
      else args.flags[k] = true;
    } else {
      args._.push(a);
    }
  }
  return args;
}

async function cmdScan(args) {
  const target = args._[1] || '.';
  const format = args.flags.format || 'cli';
  const verbose = !!args.flags.verbose;
  const output = args.flags.output;
  const noNet = !!args.flags['no-network'];
  if (noNet) process.env.AGENTIC_SECURITY_OFFLINE = '1';

  const { scan, meta } = await runScan(target, {
    changedSince: args.flags['changed-since'] || null,
    onProgress: (p) => {
      if (process.stderr.isTTY) process.stderr.write(`\r[${p.phase}] ${p.current}/${p.total} ${p.file}     `);
    },
  });
  if (process.stderr.isTTY) process.stderr.write('\r' + ' '.repeat(80) + '\r');

  const only = args.flags.only;
  if (only) {
    if (only === 'sast') { scan.secrets = []; scan.supplyChain = []; }
    if (only === 'sca')  { scan.findings = []; scan.secrets = []; }
    if (only === 'secrets') { scan.findings = []; scan.supplyChain = []; }
  }

  const includeSuppressed = !!args.flags['include-suppressed'];
  let body;
  if (format === 'json') body = JSON.stringify(toJSON(scan, meta, { includeSuppressed }), null, 2);
  else if (format === 'md' || format === 'markdown') body = toMarkdown(scan, meta);
  else if (format === 'sarif') body = JSON.stringify(toSARIF(scan, meta), null, 2);
  else if (format === 'html') body = toHTML(scan, meta);
  else body = toCLI(scan, { verbose });

  if (output) await fsp.writeFile(output, body);
  else process.stdout.write(body + '\n');

  // Always persist last scan for /security-fix and /security-report
  const stateDir = path.join(path.resolve(target), '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), JSON.stringify(toJSON(scan, meta), null, 2));

  return exitCodeFor(scan);
}

async function cmdFix(args) {
  const id = args.flags.finding;
  if (!id) { console.error('--finding <id> required'); return 4; }
  const lastScanPath = path.resolve('.agentic-security/last-scan.json');
  if (!fs.existsSync(lastScanPath)) { console.error('No prior scan found. Run `agentic-security scan` first.'); return 4; }
  const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
  const f = (last.findings || []).find(x => x.id === id);
  if (!f) { console.error(`Finding ${id} not found in last scan.`); return 4; }
  console.log(JSON.stringify(f, null, 2));
  if (f.fix?.code) {
    console.log('\n--- suggested patch ---\n');
    console.log(f.fix.code);
  }
  console.log('\nv0.1 emits the canonical fix template above. The `security-fixer` Claude subagent applies it to the file.');
  return 0;
}

async function cmdBaseline(args) {
  const sub = args._[1];
  const target = path.resolve(args._[2] || '.');
  const blPath = path.join(target, '.agentic-security', 'baseline.json');
  if (sub === 'save') {
    const lastPath = path.join(target, '.agentic-security', 'last-scan.json');
    if (!fs.existsSync(lastPath)) { console.error('Run `agentic-security scan` first.'); return 4; }
    await fsp.copyFile(lastPath, blPath);
    console.log(`Baseline saved → ${blPath}`);
    return 0;
  }
  if (sub === 'diff') {
    if (!fs.existsSync(blPath)) { console.error('No baseline. Run `agentic-security baseline save` first.'); return 4; }
    const baseline = JSON.parse(await fsp.readFile(blPath, 'utf8'));
    const { scan, meta } = await runScan(target, {});
    const current = toJSON(scan, meta);
    const baseIds = new Set(baseline.findings.map(f => f.id));
    const curIds = new Set(current.findings.map(f => f.id));
    const added = current.findings.filter(f => !baseIds.has(f.id));
    const fixed = baseline.findings.filter(f => !curIds.has(f.id));
    console.log(`Added: ${added.length}    Fixed: ${fixed.length}`);
    for (const f of added) console.log(`  + [${f.severity}] ${f.file}:${f.line}  ${f.vuln}`);
    for (const f of fixed) console.log(`  - [${f.severity}] ${f.file}:${f.line}  ${f.vuln}`);
    return added.some(f => f.severity === 'critical') ? 3 : added.length ? 1 : 0;
  }
  console.error('baseline subcommand: save | diff'); return 4;
}

async function cmdSetup(args) {
  const projectDir = path.resolve(args._[1] || '.');
  const commandsDir = path.join(projectDir, '.claude', 'commands');
  await fsp.mkdir(commandsDir, { recursive: true });
  const bundle = path.resolve(process.argv[1]);

  const commands = {
    'security-scan-all.md': `---
description: Run a full security scan (SAST + SCA + Secrets) on this project or a given path.
argument-hint: "[path]"
---
\`\`\`bash
node ${bundle} scan \${1:-.} --format cli --verbose; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
\`\`\`
After the scan, findings are saved to \`.agentic-security/last-scan.json\`.
If you see critical findings, run \`/security-fix-all --severity critical\` to remediate.
`,
    'security-fix.md': `---
description: Apply a remediation patch for a single finding from the last scan.
argument-hint: "<finding-id>"
---
\`\`\`bash
node ${bundle} fix --finding \${1}
\`\`\`
Hand the finding to the security-fixer subagent: read the file, apply the fix template adapted to the surrounding code, and run the project's test command. Do not declare done until the finding no longer reproduces on re-scan.
`,
    'security-fix-all.md': `---
description: Remediate every finding at or above a severity threshold (default: critical).
argument-hint: "[--severity critical|high|medium]"
---
Read \`.agentic-security/last-scan.json\`. For every finding at or above \`\${1:-critical}\` severity, dispatch the security-fixer subagent in sequence — not in parallel, as each fix may change subsequent findings. After each batch, re-run \`/security-scan-all\` to confirm. Stop and report if any test fails.
`,
    'security-baseline.md': `---
description: Save current findings as a baseline, or diff the current scan against the saved baseline.
argument-hint: "save|diff [path]"
---
\`\`\`bash
node ${bundle} baseline \${1} \${2:-.}
\`\`\`
- \`save\` — lock current findings as baseline; future scans only show NEW problems
- \`diff\` — re-scan and report regressions (added findings) and fixes (removed findings)
`,
    'security-report.md': `---
description: Generate an HTML security report (or JSON / Markdown / SARIF).
argument-hint: "[--format html|json|md|sarif] [--output <file>]"
---
\`\`\`bash
node ${bundle} scan . --format \${1:-html} --output \${2:-security-report.html}
\`\`\`
Default produces \`security-report.html\` — a self-contained interactive page with severity charts and filterable findings. Open with \`open security-report.html\`.
`,
    'security-sca.md': `---
description: Run a dependency vulnerability scan (SCA only) against this project.
argument-hint: "[path]"
---
\`\`\`bash
node ${bundle} scan \${1:-.} --only sca --format cli
\`\`\`
`,
    'security-secrets.md': `---
description: Scan for leaked credentials and hardcoded secrets.
argument-hint: "[path]"
---
\`\`\`bash
node ${bundle} scan \${1:-.} --only secrets --format cli
\`\`\`
`,
    'security-triage.md': `---
description: Validate scan findings for false positives and suppress confirmed FPs before reporting.
argument-hint: "[--severity critical|high|all]"
---

Read \`.agentic-security/last-scan.json\` and validate each finding at or above \`\${1:-critical}\` severity for false positives.

For each finding:
1. Read the file at the reported path and extract ±20 lines around the flagged line
2. Evaluate whether it is a **true positive** using these criteria:
   - **True positive**: user-controlled input demonstrably reaches the sink without validation — flag it
   - **False positive**: the value is validated against an allowlist / switch / explicit enum before the sink, the sink is a safe API overload (e.g. \`execFile\` with an array, parameterized query), the finding is in a test fixture or mock, or the "source" is an internal constant rather than external input
3. For each confirmed false positive, add a suppression entry to \`.agentic-security/rules.yml\`:

\`\`\`yaml
suppressions:
  - rule: "<vuln name from finding>"
    files: ["<file path>"]
    reason: "<one sentence: why this is a FP>"
\`\`\`

If \`.agentic-security/rules.yml\` does not exist, create it with the suppressions block.

After processing all findings, print a summary table:

| File:Line | Vulnerability | Verdict | Reason |
|---|---|---|---|
| ... | ... | TP / FP | ... |

Then re-run the scan so suppressions take effect:

\`\`\`bash
node ${bundle} scan . --format cli; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
\`\`\`

Do not suppress anything you are not certain is a false positive. When in doubt, mark it TP and leave remediation to \`/security-fix\`.
`,
  };

  for (const [name, content] of Object.entries(commands)) {
    await fsp.writeFile(path.join(commandsDir, name), content);
  }

  const names = Object.keys(commands).map(f => '/' + f.replace('.md', '')).join(', ');
  console.log(`✓ Installed ${Object.keys(commands).length} command shortcuts in ${commandsDir}`);
  console.log(`  ${names}`);
  console.log('');
  console.log('These work in this project only. Re-run in other projects as needed.');
  return 0;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  try {
    switch (cmd) {
      case 'scan':     process.exit(await cmdScan(args));
      case 'fix':      process.exit(await cmdFix(args));
      case 'baseline': process.exit(await cmdBaseline(args));
      case 'setup':    process.exit(await cmdSetup(args));
      case 'version':  console.log('agentic-security 0.3.0'); process.exit(0);
      case 'help': case '--help': case '-h': case undefined:
        console.log(USAGE); process.exit(cmd ? 0 : 1);
      default:
        console.error(`Unknown command: ${cmd}\n\n${USAGE}`); process.exit(4);
    }
  } catch (e) {
    console.error('agentic-security: error:', e?.stack || e?.message || e);
    process.exit(4);
  }
}

main();
