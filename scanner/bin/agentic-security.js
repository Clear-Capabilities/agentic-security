#!/usr/bin/env node
// agentic-security CLI — scan, fix, setup, version.
// Created by ClearCapabilities.Com — https://clearcapabilities.com
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { signLastScan as _signLastScan, verifyLastScan as _verifyLastScanShared } from '../src/posture/integrity.js';
import { runScan } from '../src/runScan.js';
import { toJSON, toMarkdown, toSARIF, toSTIX, toCSV, toJUnit, toCLI, toCLIByProfile, toShipVerdict, toProTable, toHTML, toSummary, exitCodeFor, normalizeFindings } from '../src/report/index.js';
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
import { applyFix, undoLast, undoAll, listHistory, preview as previewDiff, compactLog } from '../src/posture/fix-history.js';
import { syncTickets } from '../src/integrations/tickets.js';
import { decide as decideNextAction, explain as explainDecision } from '../src/posture/router.js';
import * as triage from '../src/posture/triage.js';
import { buildSlackDigest, buildDiscordDigest, postWebhook, buildJiraIssue, buildPrComment, buildSiemEvent, loadIntegrationConfig } from '../src/integrations/index.js';
import fg from 'fast-glob';

// last-scan.json integrity helpers — implementation in posture/integrity.js
// so the MCP server tools can share verification.
function _verifyLastScan(body, sigFile) {
  const v = _verifyLastScanShared(body, sigFile);
  return v;
}

const USAGE = `agentic-security <command> [options]

  🛡  Created by ClearCapabilities.Com  ·  https://clearcapabilities.com

Commands:
  secure [path] [--launch]     Smart router: tells you the single best next action
  scan [path]                  Full SAST + SCA + Secrets sweep (default: cwd)
  ship                         (internal) Vibecoder verdict — invoked by /scan-all
  ci [path]                    Baseline-aware CI scan: auto-detects PR base ref,
                               writes SARIF + JUnit + JSON, applies --fail-on policy
  fix --finding <id> [--preview|--apply]  Show diff or apply fix for a single finding
  undo [--all|--list|--compact]  Revert the most recent applied fix; --compact archives terminal entries (--retain-days N --prune-backups)
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
  mcp                          Start the MCP stdio server (scan_diff, query_taint, explain_finding, apply_fix)
  validator-cache stats|gc     Inspect / prune .agentic-security/llm-cache/ (use --older-than <days> --dry-run)
  verify [--finding <id>]      Re-run the verifier loop on last-scan findings (use --live --target <url> to execute PoCs)
  reset [--yes] [--keep ...]   Right-to-delete: wipe accumulated learned state under .agentic-security/ (preserves operator-authored config)
  rule-synth [--dry-run]       Auto-synthesise suppression rules from repeated FP verdicts (proposes — does not activate)
  version                      Print version
  banner [--full]              Print the Patch-the-frog mascot + brand lockup
  harness [path] [--include-home]   Multi-harness config audit: scans .claude/,
                               .cursor/, .codex/, .gemini/, .kiro/, .opencode/,
                               .trae/, .qwen/, .zed/, .continue/, .aider/ at the
                               project root. --include-home also sweeps ~/.
  scan-baseline --current <f> --previous <f>
                               Finding-level diff between two scan JSON outputs.
                               Reports added / removed / changed findings.

Options:
  --profile vibecoder|pro      Override profile for this run
  --only sast|sca|secrets      Limit scan to one pillar
  --format <fmt>               cli | json | md | sarif | stix | junit | csv | html | cyclonedx | spdx | pbom | aibom | aibom-md
  --pack <name>                Focus on a curated rule pack (repeatable): owasp-top-10 | cwe-top-25 | llm-security | supply-chain
  --baseline <ref>             Diff against a git ref; only findings new vs. that ref count (ci subcommand)
  --fail-on critical|high|medium|low|none  ci-mode exit policy (default: critical)
  --policy <file.rego>         ci-mode policy-as-code gate; deny[] rules fail the build (FR-SDLC-9)
  --columns standard|mitre|capec|owasp  Pro-mode column set (default: standard)
  --confidence <0..1>          Override per-profile confidence threshold
  --firehose                   Show ALL findings (ignore confidence threshold)
  --honest                     Show only high-confidence (≥0.9) findings
  --exposed-only               Filter to findings the production stack does NOT mitigate
  --mitigated-only             Filter to findings already mitigated by WAF/auth/network/flag
  --unreachable-only           Filter to findings on unreachable code paths
  --persona <name>             Filter to findings whose top-2 personas include <name>
                               (script-kiddie|opportunistic-criminal|apt-nation-state|
                                supply-chain-attacker|malicious-insider)
  --show-personas              Append per-persona top-picks block
  --show-bounty                Append predicted bug-bounty payout block
  --show-playbook              Append attack-playbook block for high+ findings
  --show-spof                  Append single-point-of-failure-controls block
  --show-trust-boundary        Append the auto-generated trust-boundary Mermaid diagram
  --show-threat-model          Append the auto-derived STRIDE threat model summary
  --show-drift                 Append calibration-drift alarms (overconfidence detection)
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
// `agentic-security banner [--full|--compact]` — Patch the frog mascot +
// brand line. `--compact` (default) prints a single coloured frog face beside
// the wordmark. `--full` prints the seven-line lockup mirroring the SVG.
// Colour is suppressed under NO_COLOR or non-TTY stderr.
function printBanner(args) {
  const useColor = !!process.stderr.isTTY && !process.env.NO_COLOR;
  const C = useColor ? {
    FROG:  '\x1b[38;2;255;107;44m',
    DEEP:  '\x1b[38;2;201;52;20m',
    CREAM: '\x1b[38;2;244;239;230m',
    DIM:   '\x1b[2m',
    BOLD:  '\x1b[1m',
    RESET: '\x1b[0m',
  } : { FROG:'', DEEP:'', CREAM:'', DIM:'', BOLD:'', RESET:'' };
  const v = '0.67.0';
  const compact = !args.flags.full;
  if (compact) {
    const lines = [
      '',
      `  ${C.FROG}╭─╮╭─╮${C.RESET}  ${C.BOLD}agentic-security${C.RESET}  ${C.DIM}·${C.RESET}  ${C.CREAM}by Clear Capabilities${C.RESET}  ${C.DIM}· v${v}${C.RESET}`,
      `  ${C.FROG}│${C.BOLD}◉${C.RESET}${C.FROG}││${C.BOLD}◉${C.RESET}${C.FROG}│${C.RESET}  ${C.DIM}Tiny.${C.RESET} ${C.FROG}${C.BOLD}Bright.${C.RESET} ${C.DIM}Watching.${C.RESET}`,
      `  ${C.FROG}╰─╯╰─╯${C.RESET}`,
      '',
    ];
    process.stdout.write(lines.join('\n'));
    return;
  }
  // Full lockup — mirrors hooks/mascot.js lockup() for first-run / banner output.
  const lines = [
    '',
    `       ${C.FROG}╭───╮ ╭───╮${C.RESET}`,
    `       ${C.FROG}│ ${C.BOLD}◉${C.RESET}${C.FROG} │ │ ${C.BOLD}◉${C.RESET}${C.FROG} │${C.RESET}        ${C.BOLD}agentic-security${C.RESET}`,
    `       ${C.FROG}╰─┬─╯ ╰─┬─╯${C.RESET}        ${C.DIM}─────────────────${C.RESET}`,
    `      ${C.FROG}╭──┴─────┴──╮${C.RESET}       ${C.CREAM}Tiny. ${C.FROG}${C.BOLD}Bright.${C.RESET}${C.CREAM} Watching.${C.RESET}`,
    `      ${C.FROG}│  ${C.DEEP}·${C.FROG}  ${C.BOLD}⌣${C.RESET}${C.FROG}  ${C.DEEP}·${C.FROG}  │${C.RESET}       ${C.CREAM}by Clear Capabilities Inc.${C.RESET}  ${C.DIM}· v${v}${C.RESET}`,
    `      ${C.FROG}╰───────────╯${C.RESET}       ${C.DIM}https://clearcapabilities.com${C.RESET}`,
    '',
  ];
  process.stdout.write(lines.join('\n'));
}

function effectiveConfidence(profile, args) {
  if (args.flags['firehose']) return 0.0;
  if (args.flags['honest']) return 0.9;
  if (args.flags['confidence'] != null) return parseFloat(args.flags['confidence']);
  return profile.confidenceMin ?? (profile.profile === 'pro' ? 0.3 : 0.9);
}

// v3 next-gen — render supplementary blocks on top of the normal CLI body.
// Each block is opt-in via a flag; renderV3Blocks returns '' when no flags
// are set, so the default output is unchanged.
function renderV3Blocks(scan, flags) {
  const out = [];
  const findings = scan.findings || [];
  if (flags['show-personas']) {
    out.push('\n── Per-attacker-persona top picks ───────────────────────────────');
    const byPersona = new Map();
    for (const f of findings) {
      if (!Array.isArray(f.personaTopTwo)) continue;
      for (const p of f.personaTopTwo) {
        if (!byPersona.has(p)) byPersona.set(p, []);
        byPersona.get(p).push(f);
      }
    }
    if (!byPersona.size) out.push('  (no findings carry persona scores yet — rerun /scan)');
    for (const [persona, items] of byPersona) {
      items.sort((a, b) => (b.personaMaxScore || 0) - (a.personaMaxScore || 0));
      out.push(`\n  ${persona} (${items.length} relevant)`);
      for (const f of items.slice(0, 3)) {
        const sev = (f.severity || '').toUpperCase();
        out.push(`    [${sev}] ${(f.vuln || '').slice(0, 60)} — ${f.file}:${f.line}`);
      }
    }
  }
  if (flags['show-bounty']) {
    out.push('\n── Predicted bug-bounty payouts ─────────────────────────────────');
    const withBounty = findings.filter(f => f.predictedBountyUsd);
    if (!withBounty.length) out.push('  (no findings carry bounty predictions — rerun /scan)');
    const sorted = withBounty.slice().sort((a, b) => (b.predictedBountyUsd.likely || 0) - (a.predictedBountyUsd.likely || 0));
    for (const f of sorted.slice(0, 15)) {
      const b = f.predictedBountyUsd;
      out.push(`  $${b.low}-$${b.high} (likely $${b.likely}, ${b.program}) — ${(f.vuln || '').slice(0, 50)}  ${f.file}:${f.line}`);
    }
  }
  if (flags['show-playbook']) {
    out.push('\n── Attack playbooks (high+ findings only) ───────────────────────');
    const withPb = findings.filter(f => f.attackPlaybook);
    if (!withPb.length) out.push('  (no high+/critical findings to show playbooks for)');
    for (const f of withPb.slice(0, 5)) {
      const pb = f.attackPlaybook;
      out.push(`\n  ${pb.cwe} — ${pb.title}  (${f.file}:${f.line})`);
      out.push('  ────────────────────────────────────');
      out.push(pb.script.split('\n').map(l => '  ' + l).join('\n'));
    }
  }
  if (flags['show-spof']) {
    out.push('\n── Single-point-of-failure controls (counterfactual) ────────────');
    const spof = scan._v3?.counterfactual?.spofControls || [];
    if (!spof.length) out.push('  (no SPOF controls detected — either no controls or no clusters of high+ findings depend on one)');
    for (const c of spof.slice(0, 10)) {
      out.push(`  ${c.control} @ ${c.location} — would expose ${c.wouldExpose} high+ findings if removed`);
    }
  }
  if (flags['show-trust-boundary']) {
    out.push('\n── Trust-boundary diagram (Mermaid) ─────────────────────────────');
    const d = scan._v3?.trustBoundaryDiagram;
    if (!d) out.push('  (no diagram — rerun /scan)');
    else {
      out.push('  ```mermaid');
      out.push(d.mermaid.split('\n').map(l => '  ' + l).join('\n'));
      out.push('  ```');
    }
  }
  if (flags['show-threat-model']) {
    out.push('\n── Auto-generated STRIDE threat model ───────────────────────────');
    const tm = scan._v3?.threatModel;
    if (!tm) out.push('  (no threat model — rerun /scan)');
    else {
      out.push(`  Assets: ${tm.summary.assetCount}   Trust boundaries: ${tm.summary.boundaryCount}`);
      for (const [cat, count] of Object.entries(tm.summary.strideCounts)) {
        out.push(`  ${cat.padEnd(22)} ${count}`);
      }
    }
  }
  if (flags['show-drift']) {
    out.push('\n── Calibration-drift alarms ─────────────────────────────────────');
    const dr = scan._v3?.calibrationDrift;
    const alarms = dr?.alarms || [];
    if (!alarms.length) out.push('  (no drift detected — confidence matches realized accuracy within threshold)');
    for (const a of alarms) {
      out.push(`  ${a.family}: reported ${(a.reportedAccuracy * 100).toFixed(0)}% vs realized ${(a.realizedAccuracy * 100).toFixed(0)}% (N=${a.sampleSize})`);
      out.push(`    ${a.recommendation}`);
    }
  }
  return out.join('\n');
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

  // v3 next-gen filter flags — operate on the production-aware composite
  // verdict. These run after every annotator so the verdict is final.
  if (args.flags['exposed-only']) {
    scan.findings = (scan.findings || []).filter(f => f.mitigationVerdict === 'exposed-in-prod' || !f.mitigationVerdict);
    scan.supplyChain = (scan.supplyChain || []).filter(f => f.mitigationVerdict === 'exposed-in-prod' || !f.mitigationVerdict);
  }
  if (args.flags['mitigated-only']) {
    scan.findings = (scan.findings || []).filter(f => f.mitigationVerdict === 'mitigated-in-prod');
    scan.supplyChain = (scan.supplyChain || []).filter(f => f.mitigationVerdict === 'mitigated-in-prod');
  }
  if (args.flags['unreachable-only']) {
    scan.findings = (scan.findings || []).filter(f => f.mitigationVerdict === 'unreachable-in-prod');
    scan.supplyChain = (scan.supplyChain || []).filter(f => f.mitigationVerdict === 'unreachable-in-prod');
  }
  // --persona <name> filter — keep only findings where the named persona
  // appears in the top-2 ranked personas for the finding.
  if (args.flags['persona']) {
    const want = String(args.flags['persona']);
    scan.findings = (scan.findings || []).filter(f =>
      Array.isArray(f.personaTopTwo) && f.personaTopTwo.includes(want)
    );
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
  else if (format === 'stix') body = JSON.stringify(toSTIX(scan, meta), null, 2);
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

  // v3 next-gen — supplementary blocks for human-readable formats. These
  // are append-only and do not change the verdict / exit code. The blocks
  // are only meaningful when v3 annotators have run (default scan path).
  if (format === 'cli' || format === 'ship' || format === 'pro' || format === 'md' || format === 'markdown') {
    body += renderV3Blocks(scan, args.flags);
  }

  if (output) await fsp.writeFile(output, body);
  else process.stdout.write(body + '\n');

  // Persist last scan for /security-fix and /security-report
  const stateDir = path.join(path.resolve(target), '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  const persistedScan = toJSON(scan, meta);
  const lastScanBody = JSON.stringify(persistedScan, null, 2);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), lastScanBody);
  try {
    await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), _signLastScan(lastScanBody));
  } catch { /* non-fatal — sig file is best-effort */ }

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
  // FR-SDLC-9: when --policy <file.rego> is supplied, evaluate against the
  // findings and fail the gate if the policy denies anything. Policy runs
  // ALONGSIDE the --fail-on threshold; either gate can fail the build.
  const policyFile = args.flags.policy;
  if (policyFile) {
    const { evaluatePolicy } = await import('../src/posture/policy-gate.js');
    const r = evaluatePolicy(path.resolve(policyFile), findings);
    if (!r.ok) {
      console.error(`[ci] policy gate error: ${r.reason || 'unknown'}`);
      return 1;
    }
    if (r.denials.length) {
      console.error(`[ci] policy gate FAILED (${r.runner}, ${r.denials.length} denial(s)):`);
      for (const d of r.denials.slice(0, 20)) console.error(`  - ${d}`);
      return 1;
    }
    process.stderr.write(`[ci] policy gate PASSED (${r.runner}, 0 denials)\n`);
  }
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
// `agentic-security harness [path] [--include-home] [--format ...]`
// Multi-harness sweep — discovers .claude/ .cursor/ .codex/ .gemini/ .kiro/
// .opencode/ .trae/ .qwen/ etc. at the project root (and optionally under ~/)
// and runs the harness-config detectors directly on each file. Bypasses
// runScan's shouldScan filter (which excludes .json / .md by default) so
// the harness-config files actually get inspected.
async function cmdHarness(args) {
  const root = path.resolve(args._[1] || '.');
  const includeHome = !!args.flags['include-home'];
  const { discoverHarnessConfigs, summarizeHarnessPresence } = await import('../src/posture/harness-discovery.js');
  const { scanClaudeSettings } = await import('../src/sast/claude-settings.js');
  const { scanClaudeMdPromptInjection } = await import('../src/sast/claude-md-prompt-injection.js');
  const { scanClaudeHookInjection } = await import('../src/sast/claude-hook-injection.js');
  const { scanMCP } = await import('../src/sast/mcp-audit.js');
  const { scanCredentials } = await import('../src/secrets/index.js');

  const fileContents = await discoverHarnessConfigs(root, { includeHome });
  const present = summarizeHarnessPresence(fileContents);
  const fileCount = Object.keys(fileContents).length;
  process.stderr.write(`[harness] discovered harnesses: ${present.length ? present.join(', ') : '(none found)'}\n`);
  process.stderr.write(`[harness] scanning ${fileCount} config file(s)${includeHome ? ' (incl. ~/)' : ''}\n`);
  if (fileCount === 0) {
    process.stdout.write('No harness configuration files found.\n');
    return 0;
  }

  const findings = [];
  const secrets = [];
  for (const [fp, content] of Object.entries(fileContents)) {
    try { findings.push(...scanClaudeSettings(fp, content)); } catch {}
    try { findings.push(...scanClaudeMdPromptInjection(fp, content)); } catch {}
    try { findings.push(...scanClaudeHookInjection(fp, content)); } catch {}
    try { findings.push(...scanMCP(fp, content)); } catch {}
    try { secrets.push(...scanCredentials(fp, content)); } catch {}
  }

  // Annotate each finding with a stable id and confidence default so the
  // ship verdict has something to render.
  for (const f of findings) {
    if (!f.confidence) f.confidence = 0.9;
  }

  const scan = {
    findings,
    secrets,
    logicVulns: [],
    supplyChain: [],
    routes: [],
    components: [],
    suppressions: [],
    filesScanned: fileCount,
    fc: fileContents,
  };
  const meta = { startedAt: new Date().toISOString(), durationMs: 0, mode: 'harness' };

  const format = args.flags.format || 'cli';
  let body;
  if (format === 'json') body = JSON.stringify(toJSON(scan, meta), null, 2);
  else if (format === 'sarif') body = JSON.stringify(toSARIF(scan, meta), null, 2);
  else if (format === 'md' || format === 'markdown') body = toMarkdown(scan, meta);
  else if (format === 'ship') body = toShipVerdict(scan, { profile: { profile: 'vibecoder', confidenceMin: 0 } });
  else body = toCLIByProfile(scan, { profile: { profile: 'pro', confidenceMin: 0 } });
  // Append a one-line harness-presence footer to CLI output.
  if ((format === 'cli' || format === 'ship') && present.length) {
    body += `\n\nHarnesses discovered: ${present.join(', ')}${includeHome ? ' (project + ~/)' : ' (project only)'}\n`;
  }
  if (args.flags.output) await fsp.writeFile(args.flags.output, body);
  else process.stdout.write(body + '\n');
  return exitCodeFor(scan);
}

// `agentic-security scan-baseline --previous a.json --current b.json [--format cli|json]`
// Finding-level diff between two scan JSON outputs. Independent of scanner
// version (use the dedicated `agentic-security-diff` bin for that).
async function cmdScanBaseline(args) {
  const prevPath = args.flags.previous;
  const currPath = args.flags.current;
  if (!prevPath || !currPath) {
    console.error('Usage: agentic-security scan-baseline --previous <a.json> --current <b.json> [--format cli|json]');
    return 2;
  }
  let prev, curr;
  try { prev = JSON.parse(fs.readFileSync(prevPath, 'utf8')); }
  catch (e) { console.error(`Cannot read previous scan: ${e.message}`); return 2; }
  try { curr = JSON.parse(fs.readFileSync(currPath, 'utf8')); }
  catch (e) { console.error(`Cannot read current scan: ${e.message}`); return 2; }
  const { diffScans, renderDiff } = await import('../src/posture/baseline-compare.js');
  const diff = diffScans(prev, curr);
  if (args.flags.format === 'json') {
    process.stdout.write(JSON.stringify({ summary: { added: diff.added.length, removed: diff.removed.length, changed: diff.changed.length, unchanged: diff.unchanged }, diff }, null, 2));
  } else {
    process.stdout.write(renderDiff(diff));
  }
  // Exit 0 if no delta, 1 if delta — useful for CI gating.
  const hasDelta = diff.added.length || diff.removed.length || diff.changed.length;
  return hasDelta ? 1 : 0;
}

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
// Premortem 3R-14: validator-cache GC. .agentic-security/llm-cache/ grows
// without bound — every cache miss writes a small JSON. After months of CI
// runs, a project carries hundreds of MB of stale verdicts whose prompt or
// model versions no longer match. This subcommand prunes entries by age and
// by prompt-version mismatch.
async function cmdValidatorCache(args) {
  const sub = args._[1] || 'help';
  const root = path.resolve(args._[2] || '.');
  const cacheDir = path.join(root, '.agentic-security', 'llm-cache');
  if (!fs.existsSync(cacheDir)) {
    console.log(`No validator cache at ${cacheDir}`);
    return 0;
  }
  if (sub === 'list' || sub === 'stats') {
    const entries = await fsp.readdir(cacheDir);
    let total = 0, bytes = 0;
    for (const f of entries) {
      if (!f.endsWith('.json')) continue;
      try {
        const st = await fsp.stat(path.join(cacheDir, f));
        total++; bytes += st.size;
      } catch {}
    }
    console.log(`validator cache: ${total} entries, ${(bytes / 1024).toFixed(1)} KB at ${cacheDir}`);
    return 0;
  }
  if (sub === 'gc' || sub === 'prune') {
    const olderThanDays = parseInt(args.flags['older-than'] || '30', 10);
    const dryRun = !!args.flags['dry-run'];
    const cutoff = Date.now() - olderThanDays * 24 * 60 * 60 * 1000;
    // Premortem 4R-15: use the public PROMPT_VERSION export rather than
    // reaching through the underscore-prefixed _internal API.
    const { PROMPT_VERSION } = await import('../src/llm-validator/index.js');
    if (!PROMPT_VERSION) {
      console.error('agentic-security: validator module did not export PROMPT_VERSION — refusing to GC (would prune everything).');
      return 4;
    }
    const wantedPromptVersion = PROMPT_VERSION;
    const entries = await fsp.readdir(cacheDir);
    let removed = 0, kept = 0, bytesFreed = 0;
    for (const f of entries) {
      if (!f.endsWith('.json')) continue;
      const fp = path.join(cacheDir, f);
      let st, body;
      try { st = await fsp.stat(fp); } catch { continue; }
      try { body = JSON.parse(await fsp.readFile(fp, 'utf8')); } catch { body = null; }
      const tooOld = st.mtimeMs < cutoff;
      const wrongVersion = body && wantedPromptVersion && body.prompt_version && body.prompt_version !== wantedPromptVersion;
      if (tooOld || wrongVersion) {
        if (!dryRun) { try { await fsp.unlink(fp); } catch {} }
        removed++; bytesFreed += st.size;
      } else { kept++; }
    }
    console.log(`${dryRun ? '[dry-run] would remove' : 'removed'} ${removed} entries (${(bytesFreed / 1024).toFixed(1)} KB), kept ${kept}.`);
    return 0;
  }
  console.error('Usage: agentic-security validator-cache <stats|gc> [path] [--older-than <days>] [--dry-run]');
  return 4;
}

// `agentic-security verify [--finding <id>] [--target <url>] [--live]`
//
// Re-runs the verifier loop over the most-recent scan. Without --live, it
// validates each finding's PoC (refuses destructive payloads, hardcoded
// metadata IPs, runaway lengths) and assigns a static verdict. With --live
// AND --target, it actually executes each PoC in a Docker sandbox (or
// subprocess fallback) against the supplied URL.
//
// FR-VER-7 fail-closed: any error → cannot-verify, never silent drop.
async function cmdVerify(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const lastScanPath = path.join(scanRoot, '.agentic-security', 'last-scan.json');
  if (!fs.existsSync(lastScanPath)) {
    console.error(`No prior scan found at ${lastScanPath}. Run \`agentic-security scan\` first.`);
    return 4;
  }
  const last = JSON.parse(await fsp.readFile(lastScanPath, 'utf8'));
  const findings = last.findings || [];
  let targetFlag = args.flags.target || process.env.AGENTIC_SECURITY_VERIFY_TARGET || null;
  const liveFlag = !!args.flags.live || process.env.AGENTIC_SECURITY_VERIFY_LIVE === '1';
  // FR-LIVE-HARNESS: if no --target was supplied, check the
  // .agentic-security/verifier-target.yaml manifest. We don't bring up the
  // target here (that's the operator's call); we surface the URL it declares.
  if (liveFlag && !targetFlag) {
    const { loadTargetManifest, describeTarget, validateTarget } =
      await import('../src/posture/verifier-target.js');
    const m = loadTargetManifest(scanRoot);
    if (m.ok) {
      const v = validateTarget(m.target);
      if (!v.ok) {
        console.error(`Verifier target manifest rejected: ${v.reason}`);
        return 4;
      }
      targetFlag = m.target.url;
      console.error(`Verifier target: ${describeTarget(m.target)}`);
      console.error(`(Read from .agentic-security/verifier-target.yaml; bring it up yourself before re-running --live.)`);
    } else {
      console.error('--live requires --target <url>, AGENTIC_SECURITY_VERIFY_TARGET, or a .agentic-security/verifier-target.yaml manifest.');
      console.error(`  Manifest check: ${m.reason}`);
      return 4;
    }
  }
  if (liveFlag) {
    // Set the env so verifier.js picks it up. We don't permanently mutate
    // process.env beyond this run.
    process.env.AGENTIC_SECURITY_VERIFY_LIVE = '1';
    process.env.AGENTIC_SECURITY_VERIFY_TARGET = targetFlag;
  }
  const { annotateVerifierVerdicts, verifierCoverageSummary } = await import('../src/posture/verifier.js');
  const filter = args.flags.finding ? findings.filter(f => f.id === args.flags.finding || f.stableId === args.flags.finding) : findings;
  if (!filter.length) {
    console.error(`No matching findings (use --finding <id>).`);
    return 4;
  }
  // Load file contents so sanitizer-absence proofs can run. Only load the
  // files referenced by the findings being verified, to keep this fast even
  // on large projects.
  const fileContents = {};
  const fileSet = new Set();
  for (const f of filter) {
    const fp = f.file || f.sink?.file;
    if (fp) fileSet.add(fp);
  }
  for (const rel of fileSet) {
    try {
      const abs = path.resolve(scanRoot, rel);
      const st = fs.statSync(abs);
      if (st.size <= 500_000) fileContents[rel] = fs.readFileSync(abs, 'utf8');
    } catch { /* file missing or unreadable; skip */ }
  }
  annotateVerifierVerdicts(filter, { target: targetFlag, fileContents });
  const sum = verifierCoverageSummary(filter);
  console.log(`Verified ${filter.length} finding(s):`);
  for (const [k, v] of Object.entries(sum)) console.log(`  ${k}: ${v}`);
  if (args.flags.verbose || args.flags.finding) {
    for (const f of filter) {
      console.log(`  ${f.file}:${f.line}  ${f.vuln}`);
      console.log(`    → ${f.verifier_verdict || 'none'} (${f.verifier_reason || 'no-reason'})${f.verifier_runner ? ' [' + f.verifier_runner + ']' : ''}`);
    }
  }
  // Persist back to last-scan.json so downstream tools see the verdicts.
  last.findings = findings;
  await fsp.writeFile(lastScanPath, JSON.stringify(last, null, 2));
  return 0;
}

// `agentic-security reset [--yes] [--keep <rules|streak|...>]`
//
// FR-LEARN-7 right-to-delete: wipes the learned-state files under
// .agentic-security/ that the engine accumulates across runs:
//
//   - validator-metrics.json     (per-CWE TP/FP scorecard)
//   - triage-feedback.json       (active-learning verdicts)
//   - llm-cache/*                (LLM validator responses)
//   - scan-history.json          (security-trend snapshots)
//   - fix-history/{log,backups}  (auto-fix history)
//   - last-scan.json[.sig]
//   - shadow-findings.json
//   - mcp-audit.log
//   - hook-throttle.json
//   - tickets.json               (two-way ticket sync state)
//
// Preserves by default:
//   - rules.yml                  (operator-authored, not learned)
//   - rules/                     (custom rule files)
//   - license-policy.yml         (operator-authored)
//   - trusted-keys.json          (signing trust root)
//   - ruleset-version.json       (pinning intent)
//
// Use --keep <names> (comma-separated) to preserve specific items;
// --yes to skip the confirmation prompt (for scripted use).
async function cmdReset(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const stateDir = path.join(scanRoot, '.agentic-security');
  if (!fs.existsSync(stateDir)) {
    console.log(`No state to reset at ${stateDir}`);
    return 0;
  }
  const WIPE = new Set([
    'validator-metrics.json',
    'triage-feedback.json',
    'scan-history.json',
    'last-scan.json',
    'last-scan.json.sig',
    'shadow-findings.json',
    'mcp-audit.log',
    'hook-throttle.json',
    'tickets.json',
    'streak.json',
    'findings.json',
    'findings.sarif',
    'findings.csv',
  ]);
  const WIPE_DIRS = new Set([
    'llm-cache',
    'fix-history',
    'fix-plans',
  ]);
  const keep = new Set((args.flags.keep || '').split(',').filter(Boolean));
  const targets = [];
  for (const entry of await fsp.readdir(stateDir, { withFileTypes: true })) {
    if (keep.has(entry.name)) continue;
    if (WIPE.has(entry.name) || WIPE_DIRS.has(entry.name)) {
      targets.push({ name: entry.name, dir: entry.isDirectory() });
    }
  }
  if (!targets.length) {
    console.log(`Nothing to reset under ${stateDir}.`);
    return 0;
  }
  console.log(`agentic-security reset — will remove from ${stateDir}:`);
  for (const t of targets) console.log(`  ${t.name}${t.dir ? '/' : ''}`);
  console.log('');
  console.log('Preserving operator-authored config: rules.yml, rules/, license-policy.yml, trusted-keys.json, ruleset-version.json');
  if (!args.flags.yes) {
    console.log('');
    console.log('Pass --yes to proceed (or --keep <name,name> to spare specific items).');
    return 0;
  }
  for (const t of targets) {
    const p = path.join(stateDir, t.name);
    try {
      if (t.dir) await fsp.rm(p, { recursive: true, force: true });
      else await fsp.rm(p, { force: true });
    } catch (e) {
      console.error(`reset: failed to remove ${p}: ${e.message}`);
    }
  }
  console.log(`Reset ${targets.length} item(s). Operator-authored config preserved.`);
  return 0;
}

// `agentic-security rule-synth [--dry-run] [--threshold N]`
//
// FR-LEARN-6: read triage-feedback.json, group repeated FP verdicts by
// (family, dir prefix), and propose a suppression YAML when ≥ threshold
// (default 5) verdicts cluster. Writes to .agentic-security/rules-proposed/.
async function cmdRuleSynth(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const { synthesizeRules } = await import('../src/posture/rule-synthesis.js');
  const proposals = synthesizeRules(scanRoot, {
    threshold: args.flags.threshold,
    dryRun: !!args.flags['dry-run'],
  });
  if (!proposals.length) {
    console.log('No proposals — either no triage feedback, or no shape clustered above threshold.');
    return 0;
  }
  console.log(`Synthesised ${proposals.length} proposal(s) in .agentic-security/rules-proposed/:`);
  for (const p of proposals) {
    console.log(`  ${p.file}  (${p.count} FPs, family=${p.family || p.rule}, glob=${p.dirGlob})`);
  }
  console.log('');
  console.log('Review each YAML before moving it to .agentic-security/rules/ to make it active.');
  return 0;
}

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
  const lastScanBody = await fsp.readFile(lastScanPath, 'utf8');
  const sigVerified = _verifyLastScan(lastScanBody, lastScanPath + '.sig');
  if (sigVerified === false) {
    console.error('Warning: last-scan.json integrity check failed — file may have been modified outside the scanner. Re-run `agentic-security scan` to refresh.');
  }
  const last = JSON.parse(lastScanBody);
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

  // --apply. Premortem 4R-8: pass stableId from the engine directly so the
  // recover() cross-check is robust against line-number drift (f.id is
  // `${file}:${line}:${rule}` and rotates when the user edits the file).
  const entry = await applyFix({
    scanRoot, file: f.file, originalContent, newContent,
    findingId: f.id, stableId: f.stableId || null,
    ruleId: f.cwe || f.title, vuln: f.vuln || f.title,
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
  if (args.flags.compact) {
    // Premortem 3R-17: surface log compaction so operators can keep the
    // fix-history dir bounded on long-lived projects.
    const retainDays = parseInt(args.flags['retain-days'] || '90', 10);
    const r = await compactLog(scanRoot, { retainDays, pruneBackups: !!args.flags['prune-backups'] });
    console.log(`Compacted: archived ${r.archived} entries, retained ${r.kept} in active log.`);
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
      case 'validator-cache': process.exit(await cmdValidatorCache(args));
      case 'verify':   process.exit(await cmdVerify(args));
      case 'reset':    process.exit(await cmdReset(args));
      case 'rule-synth': process.exit(await cmdRuleSynth(args));
      case 'digest':   process.exit(await cmdDigest(args));
      case 'setup':    process.exit(await cmdSetup(args));
      case 'mcp':      {
        const { runStdio } = await import('../src/mcp/stdio.js');
        const root = args.flags.root || process.env.AGENTIC_SECURITY_MCP_ROOT || process.cwd();
        runStdio({ sessionRoot: path.resolve(root) });
        return;
      }
      case 'cve-watch': {
        // Continuous CVE-watch daemon (one-shot). Polls OSV for the project's
        // dependency tree, fires the configured webhook on each new advisory.
        // Designed to be invoked from cron or a GitHub Action; the state file
        // (.agentic-security/cve-alerts-state.json) deduplicates across runs.
        const { runOnce } = await import('../src/posture/cve-alert-daemon.js');
        const root = args.flags.root || process.cwd();
        const r = await runOnce(path.resolve(root), {
          alertUrl:    args.flags['alert-url'],
          alertType:   args.flags['alert-type'],
          minSeverity: args.flags['min-severity'],
          dryRun:      args.flags['dry-run'] === true,
        });
        if (args.flags.json) {
          // Stringify Set/etc. safely.
          console.log(JSON.stringify(r, null, 2));
        } else if (!r.ok) {
          console.error(`cve-watch: ${r.reason || 'failed'}`);
        }
        process.exit(r.ok ? 0 : 1);
      }
      case 'version':  console.log('agentic-security 0.67.0  ·  created by ClearCapabilities.Com'); process.exit(0);
      case 'banner':   { printBanner(args); process.exit(0); }
      case 'harness':  process.exit(await cmdHarness(args));
      case 'scan-baseline': process.exit(await cmdScanBaseline(args));
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
