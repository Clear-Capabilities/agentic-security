#!/usr/bin/env node
// agentic-security CLI — scan, fix, setup, version.
// Created by ClearCapabilities.Com — https://clearcapabilities.com
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { toJSON, toMarkdown, toSARIF, toCSV, toJUnit, toCLI, toCLIByProfile, toShipVerdict, toProTable, toHTML, toSummary, exitCodeFor, normalizeFindings } from '../src/report/index.js';
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';
import { toPBOM } from '../src/sast/pipeline.js';
import { buildAIBOM, aibomToMarkdown } from '../src/posture/aibom.js';
import { recordScan, formatStreakLine, formatGradeDelta } from '../src/posture/streak.js';
import { ingestAndMerge } from '../src/sca/sarif-ingest.js';
import { loadProfile, saveProfile, detectProfile, renderAttributionLine, ATTRIBUTION, ATTRIBUTION_URL } from '../src/posture/profile.js';
import { applySuppressions, addSoftAcceptance, expiredSoftAcceptances } from '../src/posture/suppressions.js';
import { applyOverrides, validateOverrides } from '../src/posture/rule-overrides.js';
import { listPacks, loadPack, applyPacks } from '../src/posture/rule-packs.js';
import { writeLockfile, verifyLockfile, makeDeterministic, isDeterministic } from '../src/posture/deterministic.js';
import { enrichWithEPSS } from '../src/posture/epss.js';
import { enrichWithBlastRadius } from '../src/posture/blast-radius.js';
import { applyCustomRules, runRuleTests, loadCustomRules } from '../src/posture/custom-rules.js';
import { applyFix, undoLast, undoAll, listHistory, preview as previewDiff } from '../src/posture/fix-history.js';
import { syncTickets } from '../src/integrations/tickets.js';
import { decide as decideNextAction, explain as explainDecision } from '../src/posture/router.js';
import * as triage from '../src/posture/triage.js';
import { buildSlackDigest, buildDiscordDigest, postWebhook, buildJiraIssue, buildPrComment, buildSiemEvent, loadIntegrationConfig } from '../src/integrations/index.js';
import fg from 'fast-glob';

const USAGE = `agentic-security <command> [options]

  🛡  Created by ClearCapabilities.Com  ·  https://clearcapabilities.com

Commands:
  secure [path] [--launch]     Smart router: tells you the single best next action
  scan [path]                  Full SAST + SCA + Secrets sweep (default: cwd)
  ship                         (internal) Vibecoder verdict — invoked by /scan-all
  ci [path]                    Baseline-aware CI scan: auto-detects PR base ref,
                               writes SARIF + JUnit + JSON, applies --fail-on policy
  fix --finding <id> [--preview|--apply]  Show diff or apply fix for a single finding
  undo [--all|--list]          Revert the most recent applied fix (or all, or list)
  accept --finding <id>        Soft-suppress a finding for 30 days (vibecoder)
  setup [project-dir]          Install /security-* shortcut commands into a project
  profile set <vibecoder|pro>  Set or change the persona profile
  profile show                 Print current profile
  org-scan --repos <list>      Pro: scan multiple repos and produce roll-up
  triage list|assign|trend     Pro: per-finding state, MTTR, assignment
  rules validate               Pro: lint .agentic-security/rules.yml
  packs list                   List available curated rule packs
  rule list | test <glob>      List/test custom YAML rules in .agentic-security/rules/
  tickets sync --provider <p>  Two-way sync findings ↔ GitHub Issues / Linear / Jira
  digest --slack <webhook>     Vibecoder: send daily digest to Slack
  version                      Print version

Options:
  --profile vibecoder|pro      Override profile for this run
  --only sast|sca|secrets      Limit scan to one pillar
  --format <fmt>               cli | json | md | sarif | junit | csv | html | cyclonedx | spdx | pbom | aibom | aibom-md
  --pack <name>                Focus on a curated rule pack (repeatable): owasp-top-10 | cwe-top-25 | llm-security | supply-chain
  --baseline <ref>             Diff against a git ref; only findings new vs. that ref count (ci subcommand)
  --fail-on critical|high|medium|low|none  ci-mode exit policy (default: critical)
  --columns standard|mitre|capec|owasp  Pro-mode column set (default: standard)
  --confidence <0..1>          Override per-profile confidence threshold
  --firehose                   Show ALL findings (ignore confidence threshold)
  --honest                     Show only high-confidence (≥0.9) findings
  --sca-reachable-only         Only SCA findings where the vulnerable function is reachable
  --ingest-sarif <glob>        Merge external SARIF into this scan
  --scorecard                  Enrich components with OSSF Scorecard scores
  --no-network                 Skip OSV/registry queries (offline mode)
  --pr [ref]                   Diff-aware: scan only files changed since ref (auto-detects PR base)
  --deterministic              Reproducible scan: stable sort, no-network, lockfile-checked
  --no-epss                    Skip EPSS exploit-prediction enrichment (default: enabled)
  --no-blast-radius            Skip blast-radius / cost framing (default: enabled)
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

  // Deterministic mode: stable output, no-network, lockfile verification.
  if (args.flags['deterministic']) {
    process.env.AGENTIC_SECURITY_DETERMINISTIC = '1';
    process.env.AGENTIC_SECURITY_OFFLINE = '1';
    const v = verifyLockfile(targetAbs);
    if (!v.ok) {
      process.stderr.write(`[deterministic] lockfile mismatch:\n  - ${v.mismatches.join('\n  - ')}\n`);
      process.stderr.write(`[deterministic] run \`agentic-security rules lock\` to refresh.\n`);
      return 4;
    }
  }

  // --pr [ref] : friendlier alias for --changed-since that auto-detects the PR
  // base ref (GitHub/GitLab/Buildkite/Bitbucket env vars) when no value is given.
  let changedSince = args.flags['changed-since'] || null;
  if (args.flags['pr']) {
    const pr = args.flags['pr'];
    changedSince = (typeof pr === 'string' && pr !== 'true') ? pr : (detectBaseline() || 'origin/main');
    process.stderr.write(`[pr-mode] scanning files changed since: ${changedSince}\n`);
  }

  const { scan, meta } = await runScan(target, {
    changedSince,
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

  // Curated rule packs: --pack <name> (repeatable). Narrows findings to the
  // CWEs covered by the requested pack(s).
  const packArg = args.flags.pack;
  const packNames = packArg ? (Array.isArray(packArg) ? packArg : String(packArg).split(',')) : [];
  if (packNames.length) Object.assign(scan, applyPacks(scan, packNames));

  // Custom pattern-rule DSL — load .agentic-security/rules/*.yml and append findings.
  try {
    const { fileContents } = await import('../src/runScan.js').then(m => m.readTree(targetAbs));
    const customFindings = applyCustomRules(targetAbs, fileContents);
    if (customFindings.length) {
      scan.findings = [...(scan.findings || []), ...customFindings];
      if (process.stderr.isTTY) {
        process.stderr.write(`[custom-rules] +${customFindings.length} finding(s) from ${loadCustomRules(targetAbs).length} rule(s)\n`);
      }
    }
  } catch {}

  // EPSS exploit-prediction enrichment (skipped under --no-network / --deterministic).
  // Bumps severity on actively-exploited CVEs so they sort to the top.
  if (!args.flags['no-epss'] && !isDeterministic() && !noNet) {
    try { await enrichWithEPSS(scan); } catch {}
  }

  // Blast-radius narrative — purely local, always safe to run.
  if (!args.flags['no-blast-radius']) {
    try { enrichWithBlastRadius(scan, targetAbs); } catch {}
  }

  // Deterministic post-process: stable-sort findings + zero out timing.
  if (isDeterministic()) makeDeterministic(scan, meta);

  // R2: Always emit machine-readable artifacts to .agentic-security/.
  await writeMachineOutput(targetAbs, scan, meta, profile);

  const includeSuppressed = !!args.flags['include-suppressed'];
  let body;
  if (format === 'json') body = JSON.stringify(toJSON(scan, meta, { includeSuppressed }), null, 2);
  else if (format === 'md' || format === 'markdown') body = toMarkdown(scan, meta);
  else if (format === 'sarif') body = JSON.stringify(toSARIF(scan, meta), null, 2);
  else if (format === 'junit') body = toJUnit(scan, meta);
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

// /scan-all — vibecoder one-screen verdict (internal CLI subcommand: `ship`).
//
// Always returns shell exit 0 for a valid verdict (clean, low, high, or
// critical findings). Only a real engine error (exit 4) propagates. The
// slash-command UX surfaces "Not safe to deploy" as the answer the user
// asked for — it's information, not a process failure. CI consumers
// needing severity-based gating should use the `ci` subcommand which has
// explicit `--fail-on` policy control.
async function cmdShip(args) {
  const target = args._[1] || '.';
  args.flags.format = 'ship';
  const code = await cmdScan(args);
  return code >= 4 ? code : 0;
}

// Detect the PR base ref from common CI environment variables. Returns null
// if no CI baseline ref is in scope. The CLI --baseline flag takes precedence.
function detectBaseline() {
  return process.env.GITHUB_BASE_REF
    || process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME    // GitLab
    || process.env.BUILDKITE_PULL_REQUEST_BASE_BRANCH     // Buildkite
    || process.env.BITBUCKET_PR_DESTINATION_BRANCH        // Bitbucket
    || null;
}

// Translate a scan exit code (0..3) and a --fail-on threshold into a CI exit code.
// Returns 0 (pass) or 1 (fail).
function ciExitCode(scanExitCode, failOn) {
  switch (failOn) {
    case 'none':                       return 0;
    case 'critical': default:          return scanExitCode >= 3 ? 1 : 0;
    case 'high':                       return scanExitCode >= 2 ? 1 : 0;
    case 'medium':
    case 'low':                        return scanExitCode >= 1 ? 1 : 0;
  }
}

// `agentic-security ci [path] [--baseline <ref>] [--fail-on <sev>]`
// Single-shot CI command: auto-detects PR base ref, runs a baseline-aware scan,
// writes findings.{sarif,junit.xml,json} to .agentic-security/, and exits per
// the --fail-on policy.
async function cmdCi(args) {
  const target = args._[1] || '.';
  const targetAbs = path.resolve(target);
  const failOn = args.flags['fail-on'] || 'critical';
  const baseline = args.flags.baseline || detectBaseline();

  if (baseline) process.stderr.write(`[ci] baseline: ${baseline}\n`);
  else          process.stderr.write(`[ci] full scan (no baseline ref detected)\n`);

  const profile = loadPersonaProfile(targetAbs, args);
  const { scan, meta } = await runScan(target, { changedSince: baseline || null });

  // Apply suppressions + overrides + packs, mirroring cmdScan's pipeline.
  scan.findings    = applySuppressions(scan.findings    || [], targetAbs, profile);
  scan.secrets     = applySuppressions(scan.secrets     || [], targetAbs, profile);
  scan.logicVulns  = applySuppressions(scan.logicVulns  || [], targetAbs, profile);
  scan.supplyChain = applySuppressions(scan.supplyChain || [], targetAbs, profile);
  scan.findings    = applyOverrides(scan.findings    || [], targetAbs);
  scan.secrets     = applyOverrides(scan.secrets     || [], targetAbs);
  scan.logicVulns  = applyOverrides(scan.logicVulns  || [], targetAbs);
  const packArg = args.flags.pack;
  const packNames = packArg ? (Array.isArray(packArg) ? packArg : String(packArg).split(',')) : [];
  if (packNames.length) Object.assign(scan, applyPacks(scan, packNames));

  // Persist the three CI artifacts.
  const stateDir = path.join(targetAbs, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.writeFile(path.join(stateDir, 'findings.json'),
    JSON.stringify(toJSON(scan, meta), null, 2));
  await fsp.writeFile(path.join(stateDir, 'findings.sarif'),
    JSON.stringify(toSARIF(scan, meta), null, 2));
  await fsp.writeFile(path.join(stateDir, 'findings.junit.xml'),
    toJUnit(scan, meta));

  const scanCode = exitCodeFor(scan);
  const findings = normalizeFindings(scan);
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
  process.stderr.write(
    `[ci] ${findings.length} findings — ${sev.critical} critical · ${sev.high} high · ${sev.medium} medium · ${sev.low} low\n` +
    `[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}\n` +
    `[ci] fail-on=${failOn}  scan-exit=${scanCode}\n`
  );
  return ciExitCode(scanCode, failOn);
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

// /rules validate | rules lock
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
  if (sub === 'lock') {
    const { path: fp, lock } = writeLockfile(target);
    console.log(`✓ wrote ${fp}`);
    console.log(`  scanner: ${lock.scannerVersion}  rulePackHash: ${lock.rulePackHash}`);
    return 0;
  }
  console.error('rules validate | rules lock'); return 4;
}

// `agentic-security secure [--launch]` — smart router. One command picks the
// right next step based on project state.
async function cmdSecure(args) {
  const scanRoot = path.resolve(args._[1] || '.');
  const intent = args.flags.launch ? 'launch' : (args.flags.deploy ? 'deploy' : null);
  const decision = decideNextAction({ scanRoot, intent });
  process.stdout.write(explainDecision(decision));
  if (args.flags.json) process.stdout.write(JSON.stringify(decision, null, 2) + '\n');
  if (args.flags.run && /^agentic-security /.test(decision.command)) {
    process.stderr.write(`\n[secure] running: ${decision.command}\n`);
    const sub = decision.command.replace(/^agentic-security /, '').split(' ');
    process.argv = [process.argv[0], process.argv[1], ...sub];
    return main();
  }
  return 0;
}

// `agentic-security tickets sync --provider github|linear|jira [--severity high]`
async function cmdTickets(args) {
  const sub = args._[1];
  const scanRoot = path.resolve(args.flags.root || '.');
  if (sub === 'sync') {
    const provider = args.flags.provider;
    if (!provider) { console.error('--provider github|linear|jira required'); return 4; }
    const r = await syncTickets({
      scanRoot,
      provider,
      severity: args.flags.severity || 'high',
      repo: args.flags.repo,
      teamId: args.flags['team-id'],
      dryRun: !!args.flags['dry-run'],
    });
    if (!r.ok) { console.error(r.error); return 4; }
    console.log(`✓ tickets sync (${provider}${args.flags['dry-run'] ? ', dry-run' : ''})`);
    console.log(`  created: ${r.created.length}  closed: ${r.closed.length}  failed: ${r.failed.length}  tracked: ${r.totalTracked}`);
    for (const c of r.created.slice(0, 10)) console.log(`  + ${c.externalId || '(dry-run)'}  ${c.id}`);
    for (const c of r.closed.slice(0, 10)) console.log(`  ↩ ${c.externalId || '(dry-run)'}  ${c.id}`);
    for (const f of r.failed.slice(0, 10)) console.log(`  ✗ ${f.id}  ${f.error}`);
    return r.failed.length ? 1 : 0;
  }
  if (sub === 'list') {
    const { readState } = await import('../src/integrations/tickets.js');
    const state = readState(scanRoot);
    const entries = Object.entries(state);
    if (!entries.length) { console.log('No tracked tickets.'); return 0; }
    for (const [id, e] of entries) {
      console.log(`  ${e.state.padEnd(7)} ${e.provider.padEnd(7)} ${e.externalUrl || e.externalId}  ${id}`);
    }
    return 0;
  }
  console.error('Usage: agentic-security tickets sync --provider <github|linear|jira> [--repo OWNER/REPO] [--team-id ID] [--severity high|critical] [--dry-run]');
  return 4;
}

// `agentic-security rule test <fixture-glob>` — test custom rules against fixtures.
async function cmdRule(args) {
  const sub = args._[1];
  if (sub === 'test') {
    const glob = args._[2];
    if (!glob) { console.error('Usage: agentic-security rule test <fixture-glob>'); return 4; }
    const target = path.resolve(args.flags.root || '.');
    const r = await runRuleTests(target, glob);
    return r.ok ? 0 : 4;
  }
  if (sub === 'list') {
    const target = path.resolve(args.flags.root || '.');
    const rules = loadCustomRules(target);
    if (!rules.length) {
      console.log(`No custom rules in ${path.join(target, '.agentic-security/rules/')}.`);
      return 0;
    }
    for (const r of rules) console.log(`  ${r.id}  [${r.severity}]  ${r.title}`);
    return 0;
  }
  console.error('Usage: agentic-security rule test <glob>  |  rule list');
  return 4;
}

// packs list — enumerate the curated rule packs available to --pack.
async function cmdPacks(args) {
  const sub = args._[1] || 'list';
  if (sub !== 'list') { console.error('Usage: agentic-security packs list'); return 4; }
  const rows = listPacks();
  const namePad = Math.max(...rows.map(r => r.name.length));
  console.log('Available rule packs (use --pack <name>):\n');
  for (const r of rows) {
    console.log(`  ${r.name.padEnd(namePad)}  ${r.description}  [${r.cweCount} CWEs]`);
  }
  return 0;
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
  const isPreview = !!args.flags.preview;
  const isApply = !!args.flags.apply;
  const scanRoot = path.resolve(args.flags.root || '.');
  if (!id) { console.error('--finding <id> required'); return 4; }
  const lastScanPath = path.join(scanRoot, '.agentic-security', 'last-scan.json');
  if (!fs.existsSync(lastScanPath)) { console.error('No prior scan found. Run `agentic-security scan` first.'); return 4; }
  const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
  const f = (last.findings || []).find(x => x.id === id) || (last.secrets || []).find(x => x.id === id);
  if (!f) { console.error(`Finding ${id} not found in last scan.`); return 4; }

  // Default mode: print the canonical template (back-compat — security-fixer subagent applies it).
  if (!isPreview && !isApply) {
    console.log(JSON.stringify(f, null, 2));
    if (f.fix?.code) { console.log('\n--- suggested patch ---\n'); console.log(f.fix.code); }
    console.log('\nUse --preview to see a diff, or --apply to apply directly.');
    return 0;
  }

  // Both --preview and --apply require an actual replacement to operate on.
  // For now we accept either f.fix.replacement (full new file content) or
  // f.fix.replaceLine (single-line replacement). Anything else falls back
  // to the template output and tells the user to run the security-fixer subagent.
  const absFile = path.resolve(scanRoot, f.file);
  if (!fs.existsSync(absFile)) { console.error(`File not found: ${absFile}`); return 4; }
  const originalContent = await fsp.readFile(absFile, 'utf8');
  let newContent = null;
  if (typeof f.fix?.replacement === 'string') newContent = f.fix.replacement;
  else if (typeof f.fix?.replaceLine === 'string' && f.line) {
    const lines = originalContent.split('\n');
    if (lines[f.line - 1] !== undefined) {
      lines[f.line - 1] = f.fix.replaceLine;
      newContent = lines.join('\n');
    }
  }

  if (newContent === null) {
    console.error('No mechanical fix is available for this finding. Use the security-fixer subagent (default `fix` mode) and apply with `--apply` after it produces a replacement.');
    return 4;
  }

  if (isPreview) {
    console.log(previewDiff(originalContent, newContent, f.file));
    console.log('\nRun with --apply to write this change. Use `agentic-security undo` to revert.');
    return 0;
  }

  // --apply
  const entry = await applyFix({
    scanRoot, file: f.file, originalContent, newContent,
    findingId: f.id, ruleId: f.cwe || f.title, vuln: f.vuln || f.title,
  });
  console.log(`✓ applied fix ${entry.id}  (file: ${entry.file})`);
  console.log(`  backup: ${entry.backupPath}`);
  console.log(`  revert with: agentic-security undo`);
  return 0;
}

// `agentic-security undo` — revert the most recent fix (or --all).
async function cmdUndo(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  if (args.flags.list) {
    const log = listHistory(scanRoot);
    if (!log.length) { console.log('No fix history.'); return 0; }
    for (const e of log) {
      const status = e.reverted ? '↩ reverted' : '✓ applied ';
      console.log(`  ${status}  ${e.id}  ${e.file}  (${e.vuln || e.findingId})`);
    }
    return 0;
  }
  if (args.flags.all) {
    const reverted = await undoAll(scanRoot);
    if (!reverted.length) { console.log('Nothing to revert.'); return 0; }
    for (const e of reverted) console.log(`↩ reverted ${e.id}  ${e.file}`);
    console.log(`Reverted ${reverted.length} fix(es).`);
    return 0;
  }
  const r = await undoLast(scanRoot);
  if (!r) { console.log('Nothing to revert.'); return 0; }
  if (r.error) { console.error(r.error); return 4; }
  console.log(`↩ reverted ${r.id}  ${r.file}`);
  console.log(`  finding: ${r.vuln || r.findingId}`);
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
If you see critical findings, run \`/fix-all --severity critical\` to remediate.
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
    'fix-all.md': `---
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
      case 'ci':       process.exit(await cmdCi(args));
      case 'fix':      process.exit(await cmdFix(args));
      case 'undo':     process.exit(await cmdUndo(args));
      case 'accept':   process.exit(await cmdAccept(args));
      case 'profile':  process.exit(await cmdProfile(args));
      case 'triage':   process.exit(await cmdTriage(args));
      case 'org-scan': process.exit(await cmdOrgScan(args));
      case 'rules':    process.exit(await cmdRules(args));
      case 'rule':     process.exit(await cmdRule(args));
      case 'tickets':  process.exit(await cmdTickets(args));
      case 'secure':   process.exit(await cmdSecure(args));
      case 'packs':    process.exit(await cmdPacks(args));
      case 'digest':   process.exit(await cmdDigest(args));
      case 'setup':    process.exit(await cmdSetup(args));
      case 'version':  console.log('agentic-security 0.35.0  ·  created by ClearCapabilities.Com'); process.exit(0);
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
