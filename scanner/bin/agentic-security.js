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
  fix --finding <id> [--apply] Apply fix for a single finding (stub in v0.1)
  baseline save|diff [path]    Manage finding baselines
  version                      Print version

Options:
  --only sast|sca|secrets      Limit scan to one pillar
  --format json|md|sarif|cli   Report format (default: cli)
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  try {
    switch (cmd) {
      case 'scan':     process.exit(await cmdScan(args));
      case 'fix':      process.exit(await cmdFix(args));
      case 'baseline': process.exit(await cmdBaseline(args));
      case 'version':  console.log('agentic-security 0.1.0'); process.exit(0);
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
