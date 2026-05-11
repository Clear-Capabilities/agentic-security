#!/usr/bin/env node
// agentic-security CLI — scan, fix, setup, version.
// Created by ClearCapabilities.Com — https://clearcapabilities.com
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { toJSON, toMarkdown, toSARIF, toCSV, toCLI, toCLIByProfile, toShipVerdict, toProTable, toHTML, toSummary, exitCodeFor, normalizeFindings } from '../src/report/index.js';
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';
import { toPBOM } from '../src/sast/pipeline.js';
import { buildAIBOM, aibomToMarkdown } from '../src/posture/aibom.js';
import { recordScan, formatStreakLine, formatGradeDelta } from '../src/posture/streak.js';
import { ingestAndMerge } from '../src/sca/sarif-ingest.js';
import { loadProfile, saveProfile, detectProfile, renderAttributionLine, ATTRIBUTION, ATTRIBUTION_URL } from '../src/posture/profile.js';
import { applySuppressions, addSoftAcceptance, expiredSoftAcceptances } from '../src/posture/suppressions.js';
import { applyOverrides, validateOverrides } from '../src/posture/rule-overrides.js';
import * as triage from '../src/posture/triage.js';
import { buildSlackDigest, buildDiscordDigest, postWebhook, buildJiraIssue, buildPrComment, buildSiemEvent, loadIntegrationConfig } from '../src/integrations/index.js';
import fg from 'fast-glob';

const USAGE = `agentic-security <command> [options]

  🛡  Created by ClearCapabilities.Com  ·  https://clearcapabilities.com

Commands:
  scan [path]                  Full SAST + SCA + Secrets sweep (default: cwd)
  ship                         Vibecoder verdict — "safe to deploy?" yes/no
  fix --finding <id> [--apply] Apply fix for a single finding
  accept --finding <id>        Soft-suppress a finding for 30 days (vibecoder)
  setup [project-dir]          Install /security-* shortcut commands into a project
  profile set <vibecoder|pro>  Set or change the persona profile
  profile show                 Print current profile
  org-scan --repos <list>      Pro: scan multiple repos and produce roll-up
  triage list|assign|trend     Pro: per-finding state, MTTR, assignment
  rules validate               Pro: lint .agentic-security/rules.yml
  digest --slack <webhook>     Vibecoder: send daily digest to Slack
  version                      Print version

Options:
  --profile vibecoder|pro      Override profile for this run
  --only sast|sca|secrets      Limit scan to one pillar
  --format <fmt>               cli | json | md | sarif | csv | html | cyclonedx | spdx | pbom | aibom | aibom-md
  --columns standard|mitre|capec|owasp  Pro-mode column set (default: standard)
  --confidence <0..1>          Override per-profile confidence threshold
  --firehose                   Show ALL findings (ignore confidence threshold)
  --honest                     Show only high-confidence (≥0.9) findings
  --sca-reachable-only         Only SCA findings where the vulnerable function is reachable
  --ingest-sarif <glob>        Merge external SARIF into this scan
  --scorecard                  Enrich components with OSSF Scorecard scores
  --no-network                 Skip OSV/registry queries (offline mode)
  --verbose                    Include fix bodies + taxonomy in CLI output
  --output <file>              Write report to file instead of stdout
  --machine-output             Always write .agentic-security/findings.{sarif,json,csv}

Exit codes:
  0 = clean   1 = low/medium   2 = high   3 = critical   4 = error`;

// Load profile, allowing CLI flags to override. CLI flag takes precedence.
function loadPersonaProfile(scanRoot, args) {
  const flagProfile = args.flags.profile;
  const base = loadProfile(scanRoot);
  if (flagProfile === 'pro' || flagProfile === 'vibecoder') {
    return { ...base, profile: flagProfile };
  }
  return base;
}

// Compute confidence threshold from profile + flags.
function effectiveConfidence(profile, args) {
  if (args.flags['firehose']) return 0.0;
  if (args.flags['honest']) return 0.9;
  if (args.flags['confidence'] != null) return parseFloat(args.flags['confidence']);
  return profile.confidenceMin ?? (profile.profile === 'pro' ? 0.3 : 0.9);
}

// Always-on machine output (R2). Vibecoder gets JSON only; pro gets JSON+SARIF+CSV.
async function writeMachineOutput(targetAbs, scan, meta, profile) {
  const stateDir = path.join(targetAbs, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  // Always JSON (used by /security-fix and /security-report).
  await fsp.writeFile(path.join(stateDir, 'findings.json'),
    JSON.stringify(toJSON(scan, meta), null, 2));
  if (profile.profile === 'pro' || profile.machineOutput) {
    await fsp.writeFile(path.join(stateDir, 'findings.sarif'),
      JSON.stringify(toSARIF(scan, meta), null, 2));
    await fsp.writeFile(path.join(stateDir, 'findings.csv'), toCSV(scan));
  }
}

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
  const targetAbs = path.resolve(target);
  // Load persona profile (R1). Persona-aware defaults flow from here.
  const profile = loadPersonaProfile(targetAbs, args);
  const format = args.flags.format || (profile.profile === 'pro' ? 'cli' : 'ship');
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

  // 0.9.0 Feat-18: --scorecard flag enables OSSF Scorecard enrichment
  if (args.flags['scorecard']) process.env.AGENTIC_SECURITY_SCORECARD = '1';

  // 0.7.0 Feat-7: --ingest-sarif <path-or-glob> merges SARIF from external tools (Semgrep,
  // gitleaks, Bandit, Trivy, Checkov, etc.) into this scan's findings, deduping by
  // fingerprint and tracking provenance via sources[].
  if (args.flags['ingest-sarif']) {
    const glob = args.flags['ingest-sarif'];
    const paths = await fg(glob, { dot: false, onlyFiles: true });
    if (paths.length) {
      const r = ingestAndMerge(scan, paths);
      if (process.stderr.isTTY) process.stderr.write(`[ingest] merged ${r.merged} / added ${r.added} findings from ${paths.length} SARIF file(s)\n`);
    }
  }

  // 0.6.0 Feat-1: --sca-reachable-only filters to only SCA findings where the vulnerable
  // function was confirmed reachable from a route handler.
  if (args.flags['sca-reachable-only']) {
    scan.supplyChain = (scan.supplyChain || []).filter(sc =>
      sc.functionReachable === 'reachable' || sc.functionReachable !== 'unreachable'
    );
  }

  // R4: Apply persona-appropriate suppressions BEFORE rendering.
  // R9: Apply rule overrides (severity remap, disable list).
  // R3: Compute effective confidence threshold for renderers.
  const confidenceMin = effectiveConfidence(profile, args);
  const effProfile = { ...profile, confidenceMin };
  // Apply suppressions to each findings bucket (findings/secrets/logicVulns/supplyChain).
  scan.findings    = applySuppressions(scan.findings    || [], targetAbs, profile);
  scan.secrets     = applySuppressions(scan.secrets     || [], targetAbs, profile);
  scan.logicVulns  = applySuppressions(scan.logicVulns  || [], targetAbs, profile);
  scan.supplyChain = applySuppressions(scan.supplyChain || [], targetAbs, profile);
  // Apply rule overrides (severity remaps + disable list).
  scan.findings    = applyOverrides(scan.findings    || [], targetAbs);
  scan.secrets     = applyOverrides(scan.secrets     || [], targetAbs);
  scan.logicVulns  = applyOverrides(scan.logicVulns  || [], targetAbs);

  // R2: Always emit machine-readable artifacts to .agentic-security/.
  await writeMachineOutput(targetAbs, scan, meta, profile);

  const includeSuppressed = !!args.flags['include-suppressed'];
  let body;
  if (format === 'json') body = JSON.stringify(toJSON(scan, meta, { includeSuppressed }), null, 2);
  else if (format === 'md' || format === 'markdown') body = toMarkdown(scan, meta);
  else if (format === 'sarif') body = JSON.stringify(toSARIF(scan, meta), null, 2);
  else if (format === 'csv')   body = toCSV(scan);
  else if (format === 'html') body = toHTML(scan, meta);
  else if (format === 'cyclonedx' || format === 'sbom') body = JSON.stringify(toCycloneDX(scan, meta), null, 2);
  else if (format === 'spdx')                            body = JSON.stringify(toSPDX(scan, meta), null, 2);
  else if (format === 'pbom')                            body = JSON.stringify(toPBOM(scan.fc || {}, meta), null, 2);
  else if (format === 'aibom')                           body = JSON.stringify(buildAIBOM(scan, scan.fc || {}, meta), null, 2);
  else if (format === 'aibom-md')                        body = aibomToMarkdown(buildAIBOM(scan, scan.fc || {}, meta));
  else if (format === 'ship')  body = toShipVerdict(scan, { profile: effProfile });
  else if (format === 'pro')   body = toProTable(scan, { profile: effProfile, columns: args.flags.columns });
  else if (format === 'cli')   body = toCLIByProfile(scan, { profile: effProfile, columns: args.flags.columns, verbose });
  else body = toSummary(scan);

  if (output) await fsp.writeFile(output, body);
  else process.stdout.write(body + '\n');

  // Persist last scan for /security-fix and /security-report
  const stateDir = path.join(path.resolve(target), '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  const persistedScan = toJSON(scan, meta);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), JSON.stringify(persistedScan, null, 2));

  // 0.14.0 — update streak / achievements after every full scan. Suppress
  // streak side effects when the user only wants raw JSON output (CI piping).
  try {
    const streak = recordScan(stateDir, persistedScan);
    // Print celebration / streak line to stderr so it doesn't pollute --format json
    if (process.stderr.isTTY && format !== 'json' && format !== 'sarif') {
      const delta = formatGradeDelta(streak);
      const line = formatStreakLine(streak);
      if (delta) process.stderr.write('\n' + delta + '\n');
      if (line) process.stderr.write('🛡️  ' + line + '\n');
    }
  } catch {}

  return exitCodeFor(scan);
}

// /ship — vibecoder one-screen verdict.
async function cmdShip(args) {
  const target = args._[1] || '.';
  args.flags.format = 'ship';
  return cmdScan(args);
}

// /accept --finding <id> --reason "..."  (vibecoder soft 30-day suppression)
async function cmdAccept(args) {
  const target = path.resolve(args._[1] || '.');
  const id = args.flags.finding;
  if (!id) { console.error('--finding <id> required'); return 4; }
  const reason = args.flags.reason || 'vibecoded for now';
  const lastScanPath = path.join(target, '.agentic-security', 'findings.json');
  if (!fs.existsSync(lastScanPath)) { console.error('No prior scan found. Run `agentic-security scan` first.'); return 4; }
  const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
  const f = (last.findings || []).find(x => x.id === id);
  if (!f) { console.error(`Finding ${id} not found.`); return 4; }
  // Disallow accepting criticals without explicit flag.
  if (f.severity === 'critical' && !args.flags['accept-critical']) {
    console.error('Cannot soft-accept a CRITICAL finding without --accept-critical.');
    return 4;
  }
  const expires = addSoftAcceptance(target, f, reason);
  console.log(`✓ Accepted finding ${id} until ${expires}.`);
  console.log(`  ${ATTRIBUTION}`);
  return 0;
}

// /profile set <name> | /profile show
async function cmdProfile(args) {
  const target = path.resolve(args._[2] || '.');
  const sub = args._[1];
  if (sub === 'show') {
    const p = loadProfile(target);
    console.log(`Profile: ${p.profile}`);
    console.log(`  confidence threshold: ${p.confidenceMin}`);
    console.log(`  taxonomy visible:     ${p.showTaxonomy}`);
    console.log(`  suppression schema:   ${p.suppression}`);
    console.log(`  machine output:       ${p.machineOutput ? 'always' : 'on-request'}`);
    console.log(`  ${ATTRIBUTION}`);
    return 0;
  }
  if (sub === 'set') {
    const name = args._[2];
    if (name !== 'vibecoder' && name !== 'pro') {
      console.error('profile set <vibecoder|pro>'); return 4;
    }
    const next = saveProfile(target, { profile: name });
    console.log(`✓ Profile set to: ${next.profile}`);
    return 0;
  }
  if (sub === 'detect') {
    const detected = detectProfile(target);
    console.log(`Detected profile: ${detected}`);
    return 0;
  }
  console.error('profile show | profile set <vibecoder|pro> | profile detect');
  return 4;
}

// /triage list | assign | transition | trend
async function cmdTriage(args) {
  const target = path.resolve(args._[args._.length - 1] && !args._[args._.length - 1].startsWith('--') ? args._[args._.length - 1] : '.');
  const profile = loadProfile(target);
  if (profile.profile !== 'pro') {
    console.error('Triage is a pro-mode feature. Run `agentic-security profile set pro` to enable.');
    return 4;
  }
  const sub = args._[1];
  // Sync first so list reflects the latest scan.
  const lastScanPath = path.join(target, '.agentic-security', 'findings.json');
  if (fs.existsSync(lastScanPath)) {
    const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
    triage.syncWithScan(target, last.findings || []);
  }
  if (sub === 'list') {
    const filter = {};
    if (args.flags.status) filter.state = args.flags.status;
    if (args.flags.severity) filter.severity = args.flags.severity;
    if (args.flags.assignee) filter.assignee = args.flags.assignee;
    if (args.flags.unassigned) filter.unassigned = true;
    const items = triage.list(target, filter);
    const hdr = ['ID', 'Severity', 'State', 'Assignee', 'File:Line', 'Vuln'].join('  ');
    console.log(hdr);
    console.log('─'.repeat(80));
    for (const t of items.slice(0, 50)) {
      console.log([
        t.id.slice(0, 16),
        (t.severity || '').padEnd(8),
        t.state.padEnd(13),
        (t.assignee || '—').padEnd(20),
        `${t.file}:${t.line}`.padEnd(40),
        t.vuln,
      ].join('  '));
    }
    return 0;
  }
  if (sub === 'assign') {
    const id = args._[2];
    const assignee = args._[3] || args.flags.assignee;
    if (!id || !assignee) { console.error('triage assign <id> <assignee>'); return 4; }
    const r = triage.assign(target, id, assignee);
    if (!r.ok) { console.error(r.error); return 4; }
    console.log(`✓ Assigned ${id} to ${assignee}`); return 0;
  }
  if (sub === 'transition') {
    const id = args._[2];
    const state = args._[3];
    const r = triage.transition(target, id, state, args.flags.comment);
    if (!r.ok) { console.error(r.error); return 4; }
    console.log(`✓ ${id} → ${state}`); return 0;
  }
  if (sub === 'trend') {
    const days = parseInt(args.flags.since || '30', 10);
    const t = triage.trend(target, days);
    console.log(`Trend over ${t.sinceDays} days:`);
    console.log(`  Opened:  ${t.opened}`);
    console.log(`  Closed:  ${t.closed}`);
    console.log(`  Net:     ${t.net} (${t.net <= 0 ? 'improving' : 'regressing'})`);
    console.log(`  Open:    critical=${t.openBySev.critical} high=${t.openBySev.high} medium=${t.openBySev.medium} low=${t.openBySev.low}`);
    if (t.medianMttrDays != null) console.log(`  MTTR median: ${t.medianMttrDays.toFixed(1)} days`);
    console.log(`  Total open: ${t.totalOpen}`);
    return 0;
  }
  console.error('triage list | assign <id> <assignee> | transition <id> <state> | trend [--since N]');
  return 4;
}

// /org-scan — clone or visit multiple repos, run scan, produce roll-up.
async function cmdOrgScan(args) {
  const reposCsv = args.flags.repos;
  if (!reposCsv) { console.error('--repos <path1,path2,...> required'); return 4; }
  const repos = reposCsv.split(',').map(s => s.trim()).filter(Boolean);
  const workers = parseInt(args.flags.workers || '4', 10);
  const rollup = { scannedAt: new Date().toISOString(), repos: [] };

  console.log(`🛡  agentic-security org-scan — ${repos.length} repo(s), ${workers} worker(s)`);
  console.log(`   created by ClearCapabilities.Com`);
  console.log('');

  // Simple bounded concurrency.
  const queue = repos.slice();
  const active = [];
  while (queue.length || active.length) {
    while (active.length < workers && queue.length) {
      const repo = queue.shift();
      const p = (async () => {
        const t0 = Date.now();
        try {
          const { scan, meta } = await runScan(repo);
          const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
          for (const f of scan.findings || []) counts[f.severity || 'medium']++;
          for (const f of scan.secrets || []) counts[f.severity || 'high']++;
          rollup.repos.push({
            repo,
            scanned: scan.filesScanned || 0,
            critical: counts.critical, high: counts.high, medium: counts.medium, low: counts.low,
            elapsed_ms: Date.now() - t0,
          });
          console.log(`  ✓ ${repo.padEnd(60)} crit=${counts.critical} high=${counts.high} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
        } catch (e) {
          rollup.repos.push({ repo, error: e.message });
          console.log(`  ✗ ${repo.padEnd(60)} ERROR: ${e.message}`);
        }
      })();
      active.push(p);
      p.finally(() => { const i = active.indexOf(p); if (i >= 0) active.splice(i, 1); });
    }
    if (active.length) await Promise.race(active);
  }

  const total = rollup.repos.reduce((acc, r) => ({
    critical: acc.critical + (r.critical || 0), high: acc.high + (r.high || 0),
    medium: acc.medium + (r.medium || 0), low: acc.low + (r.low || 0),
  }), { critical: 0, high: 0, medium: 0, low: 0 });
  console.log('');
  console.log('Org-wide summary:');
  console.log(`  Critical: ${total.critical}  High: ${total.high}  Medium: ${total.medium}  Low: ${total.low}`);
  const sorted = rollup.repos.filter(r => !r.error).sort((a, b) => (b.critical + b.high) - (a.critical + a.high)).slice(0, 5);
  if (sorted.length) {
    console.log('');
    console.log('Top 5 repos by critical+high:');
    for (const r of sorted) console.log(`  ${r.repo.padEnd(60)} crit=${r.critical} high=${r.high}`);
  }
  // Write rollup JSON.
  const out = args.flags.output || 'org-scan-' + new Date().toISOString().slice(0, 10) + '.json';
  await fsp.writeFile(out, JSON.stringify(rollup, null, 2));
  console.log(`\nFull rollup: ${out}`);
  return 0;
}

// /rules validate
async function cmdRules(args) {
  const target = path.resolve(args._[2] || '.');
  const sub = args._[1];
  if (sub === 'validate') {
    const r = validateOverrides(target);
    if (r.ok) { console.log('✓ rules.yml is valid'); return 0; }
    console.error('rules.yml has errors:');
    for (const e of r.errors) console.error('  - ' + e);
    return 4;
  }
  console.error('rules validate'); return 4;
}

// /digest --slack <webhook> | --discord <webhook>
async function cmdDigest(args) {
  const target = path.resolve(args._[1] || '.');
  const profile = loadProfile(target);
  const lastScanPath = path.join(target, '.agentic-security', 'findings.json');
  if (!fs.existsSync(lastScanPath)) { console.error('No prior scan found.'); return 4; }
  const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
  const findings = (last.findings || []).filter(f => f.severity === 'critical' || f.severity === 'high');
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of (last.findings || [])) summary[f.severity || 'medium']++;
  const project = args.flags.project || path.basename(target);
  if (args.flags.slack) {
    const payload = buildSlackDigest(findings, summary, { project });
    const r = await postWebhook(args.flags.slack, payload);
    console.log(r.ok ? `✓ Slack digest sent` : `✗ Slack failed: ${r.reason || r.status}`);
    return r.ok ? 0 : 4;
  }
  if (args.flags.discord) {
    const payload = buildDiscordDigest(findings, summary, { project });
    const r = await postWebhook(args.flags.discord, payload);
    console.log(r.ok ? `✓ Discord digest sent` : `✗ Discord failed: ${r.reason || r.status}`);
    return r.ok ? 0 : 4;
  }
  console.error('digest --slack <url> OR digest --discord <url>'); return 4;
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
node ${bundle} scan \${1:-.}; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
\`\`\`
Output is a grouped summary: severity counts, finding types by frequency, top affected files.
Use \`--format cli\` for the full per-finding list. Findings are always saved to \`.agentic-security/last-scan.json\`.
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
node ${bundle} scan .; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
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
      case 'ship':     process.exit(await cmdShip(args));
      case 'fix':      process.exit(await cmdFix(args));
      case 'accept':   process.exit(await cmdAccept(args));
      case 'profile':  process.exit(await cmdProfile(args));
      case 'triage':   process.exit(await cmdTriage(args));
      case 'org-scan': process.exit(await cmdOrgScan(args));
      case 'rules':    process.exit(await cmdRules(args));
      case 'digest':   process.exit(await cmdDigest(args));
      case 'setup':    process.exit(await cmdSetup(args));
      case 'version':  console.log('agentic-security 0.16.2  ·  created by ClearCapabilities.Com'); process.exit(0);
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
