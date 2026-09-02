#!/usr/bin/env node
// agentic-security CLI — scan, fix, setup, version.
// Created by ClearCapabilities.Com — https://clearcapabilities.com
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { createRequire } from 'node:module';
const __require = createRequire(import.meta.url);
const PKG_VERSION = __require('../package.json').version;
import { signLastScan as _signLastScan, verifyLastScan as _verifyLastScanShared } from '../src/posture/integrity.js';
import { isProvenanceHealthy, sanitizeForTerminal } from '../src/posture/provenance/schema.js';
import { runScan } from '../src/runScan.js';

// Every command is dispatched as `process.exit(await cmdX(args))`, and
// process.exit() does NOT flush an asynchronous stdout. stdout is asynchronous
// whenever it is a PIPE — which is every `> file`, `| jq`, and CI capture — so
// anything still buffered when the process exits is discarded at the pipe
// boundary: 64 KiB on macOS and Linux.
//
// That silently truncated `scan --format sarif` mid-token for any project
// large enough to matter, i.e. the primary CI integration path, while still
// exiting with a normal status. The consumer sees a JSON parse error with no
// connection to its cause, or ingests a partial finding set.
//
// fs.writeSync(1, …) hands the bytes to the OS before returning, so a later
// exit cannot lose them. A non-blocking pipe can still short-write or raise
// EAGAIN, hence the loop — a partial write that is not retried is the same
// truncation bug wearing a different hat.
function writeStdout(s) {
  const buf = Buffer.from(String(s), 'utf8');
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(1, buf, off, buf.length - off);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;   // pipe full; the reader will drain it
      if (e.code === 'EPIPE') return;      // reader closed (`| head`) — not our error
      throw e;
    }
  }
}
import { toJSON, toMarkdown, toSARIF, toSTIX, toCSV, toJUnit, toCLI, toCLIByProfile, toShipVerdict, toProTable, toHTML, toSummary, toVex, exitCodeFor, normalizeFindings } from '../src/report/index.js';
import { toOSCAL } from '../src/report/oscal.js';

// Formats whose output is a machine artifact, not something a human reads in a
// terminal. Three separate copies of this list used to be spelled out inline —
// the MTTR line, the fix-duration line and the streak line — and each new
// format had to be added to all three or it silently got human chatter
// interleaved into its stdout/stderr. One list, one place to update.
const MACHINE_FORMATS = new Set([
  'json', 'sarif', 'oscal', 'cyclonedx', 'sbom', 'spdx', 'vex', 'openvex', 'pbom', 'aibom',
]);
function isMachineFormat(fmt) { return MACHINE_FORMATS.has(String(fmt)); }
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';
import { toPBOM } from '../src/sast/pipeline.js';
import { buildAIBOM, aibomToMarkdown } from '../src/posture/aibom.js';
import { recordScan, formatStreakLine, formatGradeDelta } from '../src/posture/streak.js';
import { loadProfile, saveProfile, detectProfile, renderAttributionLine, ATTRIBUTION, ATTRIBUTION_URL } from '../src/posture/profile.js';
import { applySuppressions, addSoftAcceptance, expiredSoftAcceptances } from '../src/posture/suppressions.js';
import { applyOverrides, validateOverrides, suppressionReport, renderSuppressionSummary } from '../src/posture/rule-overrides.js';
import { listPacks, loadPack, applyPacks } from '../src/posture/rule-packs.js';
import { writeLockfile, verifyLockfile, makeDeterministic, isDeterministic } from '../src/posture/deterministic.js';
import { enrichWithEPSS } from '../src/posture/epss.js';
import { enrichWithBlastRadius } from '../src/posture/blast-radius.js';
import { applyCustomRules, runRuleTests, loadCustomRules, customRulesFreshness } from '../src/posture/custom-rules.js';
import { undoLast, undoAll, listHistory, preview as previewDiff, compactLog } from '../src/posture/fix-history.js';
import { applyVerifiedFix, confinePath } from '../src/fix/apply-fix-service.js';
import { syncTickets } from '../src/integrations/tickets.js';
import { decide as decideNextAction, explain as explainDecision } from '../src/posture/router.js';
import * as triage from '../src/posture/triage.js';
import { buildSlackDigest, buildDiscordDigest, postWebhook, buildJiraIssue, buildPrComment, buildSiemEvent, loadIntegrationConfig } from '../src/integrations/index.js';

import { stateDir, statePath } from '../src/posture/state-dir.js';
import { listGeneratedArtifacts } from '../src/posture/artifact-registry.js';
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
                               --expired    only remove artifacts past their retention-class TTL
                               Every run writes a deletion-report.json proving what was planned/deleted/preserved/failed.
  export --out <dir>           Copy every present .agentic-security/ artifact to <dir> with a manifest (export-manifest.json,
                               unsigned) proving what was exported and what failed — for migration or legal-preservation purposes.
  legal-hold add --artifact <name> --owner <id> --reason <text> [--expires <date>]
                               Exempt a registered artifact from retention TTL and reset (both --expired and plain)
  legal-hold remove --artifact <name>   Lift a hold
  legal-hold list [--all]      List active holds (--all also shows past holds whose expires_at has passed)
  calibration-feedback record --finding-id <id> --outcome accepted-risk|realized-incident [--note <text>]
                               Opt-in: report a real-world outcome for a past finding, for calibration validation
  calibration-report [--format cli|json]   Aggregated, privacy-preserving calibration report from recorded feedback
  rule-synth [--dry-run]       Auto-synthesise suppression rules from repeated FP verdicts (proposes — does not activate)
  compliance [--privacy]       Assess the last scan against NIST Privacy Framework 1.1
                               --list                 show bundled + BYO frameworks
                               --walkthrough <id>     auditor narrative for any framework
                               --report <id>          synonym for --walkthrough
                               --gap                  only the failing controls
                               --format cli|json|md|oscal   (default cli)
                               --format oscal         NIST OSCAL assessment-results.
                                                      Controls the engine could not
                                                      decide carry NO finding — see
                                                      docs/OSCAL.md.
                               --fail-on gap          exit 1 when a control is failing
                               Reads .agentic-security/last-scan.json — run a scan first.
  version                      Print version
  banner [--full]              Print the Patch-the-frog mascot + brand lockup
  harness [path] [--include-home]   Multi-harness config audit: scans .claude/,
                               .cursor/, .codex/, .gemini/, .kiro/, .opencode/,
                               .trae/, .qwen/, .zed/, .continue/, .aider/ at the
                               project root. --include-home also sweeps ~/.
  scan-baseline --current <f> --previous <f>
                               Finding-level diff between two scan JSON outputs.
                               Reports added / removed / changed findings.
  explore [path] [--port <n>] [--keep-open]
                               Start a local, read-only server over an
                               already-scanned lineage graph (run
                               AGENTIC_SECURITY_LINEAGE_DEEP=1 scan first)
  dataflow export [path] --format png|pdf|svg|json|csv|html --output <file>
                               Export the already-scanned lineage graph.
                               --view architecture|privacy|trace|inventory  (default: architecture)
                               --size standard|2x    AC-23 pinned PNG sizes (default: standard)
                               --width <n> --height <n>   custom PNG size (mutually exclusive with --size)
                               --no-redact            include unredacted content (json/html only; no-op + warning for csv)
                               --filter <path.json>   {nodeIds,edgeIds} to scope the export

Options:
  --profile vibecoder|pro      Override profile for this run
  --only sast|sca|secrets      Limit scan to one pillar
  --format <fmt>               cli | json | md | sarif | oscal | stix | junit | csv | html | cyclonedx | spdx | pbom | aibom | aibom-md
  --pack <name>                Focus on a curated rule pack (repeatable): owasp-top-10 | cwe-top-25 | llm-security | supply-chain
  --baseline <ref>             Diff against a git ref; only findings new vs. that ref count (ci subcommand)
  --fail-on critical|high|medium|low|none  ci-mode exit policy (default: critical)
  --fail-on-new                (ci) block ONLY on findings this PR introduced vs
                               the baseline ref — never the pre-existing backlog
  --policy <file.rego>         ci-mode policy-as-code gate; deny[] rules fail the build (FR-SDLC-9)
  --assurance advisory|standard|strict  (ci) incomplete-analysis behavior (default: standard).
                               strict fails the build when any analyzer failed, timed out,
                               or was silently skipped by policy — independent of --fail-on (FR-204)
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
  --scorecard                  Enrich components with OSSF Scorecard scores
  --no-network                 Skip OSV/registry queries (offline mode)
  --pr [ref]                   Diff-aware: scan only files changed since ref (auto-detects PR base)
  --deterministic              Reproducible scan: stable sort, no-network, lockfile-checked
  --incremental                Reuse taint summaries from prior scans (speeds up deep mode in CI)
  --set-baseline               Save current findings as baseline (suppresses pre-existing issues)
  --since-baseline             Only show findings NOT in the saved baseline
  --hide-proven-safe           Drop findings discharged by a flow proof (provably safe)
  --secret-history             Also sweep recent git history for committed secrets
  --validate-secrets           Label each detected secret live/dead/unknown (opt-in, network, offline-degrading)
                               (removed from HEAD but recoverable from .git)
  --history-depth <n>          Commits to sweep with --secret-history (default 50)
  --no-epss                    Skip EPSS exploit-prediction enrichment (default: enabled)
  --no-blast-radius            Skip blast-radius / cost framing (default: enabled)
  --verbose                    Include fix bodies + taxonomy in CLI output
                               (with --firehose, also prints each finding's git-origin provenance)
  --output <file>              Write report to file instead of stdout
  --machine-output             Always write .agentic-security/findings.{sarif,json,csv}

Finding provenance (which commit introduced each finding):
  --provenance <standard|deep> Resolution depth (default: standard; deep explores non-linear ancestry — merges, reverts, cherry-picks)
  --no-provenance              Skip git-history provenance entirely (findings report not_available)
  --provenance-since <ref>     Do not walk history earlier than this git ref/commit
  --provenance-timeout <ms>    Whole-scan provenance budget in MILLISECONDS (default 60000)
  --include-author-email       Keep commit author emails in output (redacted by default)
  --pseudonymize-authors       Replace commit author names with a stable Contributor-XXXXXXXX id
  --require-provenance         Report unresolved provenance as a scan-health condition
                               (downgrades scanHealth.status to 'partial'; never changes the exit code)

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
  const v = PKG_VERSION;
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
// SHA-256 of the running bundle, read from the sidecar `npm run build` emits
// NEXT TO the bundle. Running from source (bin/ + src/) yields 'unavailable'
// rather than the checkout's dist hash: src and a previously-built dist can
// disagree, and attesting a bundle that did not produce this run would be a
// false claim.
function _bundleSha() {
  const here = path.dirname(new URL(import.meta.url).pathname);
  try {
    const raw = fs.readFileSync(path.join(here, 'agentic-security.mjs.sha256'), 'utf8').trim();
    const m = /^([0-9a-f]{64})\b/.exec(raw);
    if (m) return m[1];
  } catch { /* not running from the bundle */ }
  return 'unavailable';
}

async function writeMachineOutput(targetAbs, scan, meta, profile, args) {
  const stateDirPath = stateDir(targetAbs);
  const { isSafeStateDir: _isSafe, stateWritesEnabled: _writesOn } = await import('../src/posture/state-dir.js');
  // Read-only scan (NON_MUTATING_SCAN_PRD S1). These writes bypass
  // safeWriteState because they are async, so the switch is checked here — the
  // same refusal path the project-root check already uses.
  if (!_writesOn() || !_isSafe(stateDirPath)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') process.stderr.write(`[agentic-security] refusing to write machine output at ${stateDirPath} — no project marker\n`);
    return;
  }
  await fsp.mkdir(stateDirPath, { recursive: true });
  // Always JSON (used by /security-fix and /security-report).
  await fsp.writeFile(path.join(stateDirPath, 'findings.json'),
    JSON.stringify(toJSON(scan, meta), null, 2));
  if (profile.profile === 'pro' || profile.machineOutput || (args && args.flags['machine-output'])) {
    await fsp.writeFile(path.join(stateDirPath, 'findings.sarif'),
      JSON.stringify(toSARIF(scan, meta), null, 2));
    await fsp.writeFile(path.join(stateDirPath, 'findings.csv'), toCSV(scan));
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

// The only values `--provenance` accepts. Used both to validate an inline
// `--provenance=<mode>` and to decide whether a following bare token is this
// flag's value at all — see the comment inside the parser.
const PROVENANCE_MODES = new Set(['standard', 'deep']);

// Finding Provenance (M0/M1) — CLI flags that set the env vars engine.js
// (Task 15) and report/index.js (Task 16) already read:
// AGENTIC_SECURITY_NO_PROVENANCE, AGENTIC_SECURITY_PROVENANCE_MODE,
// AGENTIC_SECURITY_PROVENANCE_SINCE, AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS,
// AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL,
// AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS. `requireProvenance` is consumed
// directly by cmdScan (post-scan scanHealth augmentation), not via an env var.
// Kept as a pure function (argv in, plain object out) so it's unit-testable
// without invoking the CLI dispatch or touching process.env.
export function parseProvenanceFlags(argv) {
  // OPT-IN, not opt-out (0.145.0). Provenance was on by default through M0-M4,
  // and the release gate caught what that costs: time-to-first-finding on a
  // 207-file tree went 4.5s -> 45s, a 7.6x regression on the ONE metric
  // bench/ttff/runner.mjs's own header calls the binding constraint for this
  // product's vibecoder ICP ("how long until the FIRST useful result, not
  // aggregate F1"). Resolving history for every finding is simply not what a
  // first-time user is waiting for. It stays one flag away, and CI/compliance
  // callers that DO want it pass `--provenance` explicitly.
  //
  // `disabled` therefore starts true, and any provenance-shaped flag flips it
  // off — asking for `--provenance-since` or `--require-provenance` is asking
  // for provenance, and making the user also pass a bare `--provenance`
  // alongside it would be a papercut with no upside.
  const result = { mode: 'standard', since: null, timeoutMs: undefined, includeEmail: false, pseudonymize: false, requireProvenance: false, disabled: true, warning: null };
  const warnings = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (typeof a !== 'string' || !a.startsWith('--')) continue;
    // BOTH `--flag value` and `--flag=value`, because parseArgs() above accepts
    // both for every other flag in this CLI and an operator has no way to know
    // this one parser is different. Exact-string matching silently ignored
    // `--provenance=deep` / `--provenance-since=v1.0.0` /
    // `--provenance-timeout=30000` — no warning, defaults quietly used.
    //
    // Split on the FIRST `=` and keep the whole remainder, rather than
    // parseArgs's `split('=', 2)` which drops everything after a second `=`.
    // A git ref (`--provenance-since=refs/tags/v1=rc1`) is a legal value and
    // truncating it would be a worse failure than the one being fixed.
    const eq = a.indexOf('=');
    const key = eq === -1 ? a : a.slice(0, eq);
    const inline = eq === -1 ? undefined : a.slice(eq + 1);
    // `--flag value` consumes the NEXT argv entry only when there is no inline
    // value; a value that itself starts with `--` is another flag, not this
    // one's argument.
    const takeValue = () => {
      if (inline !== undefined) return inline;
      const next = argv[i + 1];
      if (next !== undefined && !String(next).startsWith('--')) { i++; return next; }
      return undefined;
    };

    if (key === '--no-provenance') result.disabled = true;
    else if (key === '--provenance') {
      result.disabled = false;
      // The SPACE form only claims the next token when it actually names a
      // mode. `--provenance` is legal on its own (provenance is on by default;
      // the flag is how you say "standard, explicitly"), and this CLI's target
      // is nearly always a positional — `scan --provenance ./src` must scan
      // `./src`, not report `unrecognised mode './src'`. parseArgs() does its
      // own positional collection over the same argv, so consuming here never
      // steals the path from it, but the warning would still be a lie.
      //
      // The INLINE form has no such ambiguity: `--provenance=x` can only ever
      // be a mode, so an unknown one is a typo worth naming.
      const v = inline !== undefined
        ? inline
        : (PROVENANCE_MODES.has(String(argv[i + 1])) ? argv[++i] : undefined);
      if (v === 'deep' || v === 'standard' || v === undefined) {
        result.mode = v || 'standard';
      } else {
        warnings.push(`unrecognised --provenance mode '${v}' (expected standard|deep), running standard`);
      }
    } else if (key === '--provenance-since') { result.since = takeValue() ?? null; result.disabled = false; }
    else if (key === '--provenance-timeout') {
      // MILLISECONDS, and validated as such. `parseInt` alone turned
      // `--provenance-timeout 30s` into 30 — a 30-MILLISECOND budget that
      // expires before the first `git blame` returns, so every finding came
      // back `budget_exhausted` and nothing said why. A missing value produced
      // NaN, which `if (_provFlags.timeoutMs)` then discarded silently. Both
      // now warn and fall back to the engine default rather than inventing a
      // budget the operator did not ask for. The unit is fixed by the env var
      // this flag feeds, AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS.
      const raw = takeValue();
      if (raw === undefined) {
        warnings.push('--provenance-timeout requires a value in milliseconds; using the default budget');
      } else if (!/^\d+$/.test(String(raw).trim()) || parseInt(raw, 10) <= 0) {
        warnings.push(`--provenance-timeout expects a positive integer number of MILLISECONDS, got '${raw}'; using the default budget`);
      } else {
        result.timeoutMs = parseInt(raw, 10);
        result.disabled = false;
      }
    }
    else if (key === '--include-author-email') { result.includeEmail = true; result.disabled = false; }
    else if (key === '--pseudonymize-authors') { result.pseudonymize = true; result.disabled = false; }
    else if (key === '--require-provenance') { result.requireProvenance = true; result.disabled = false; }
  }
  // One field, so a caller that prints `warning` cannot drop the second one.
  result.warning = warnings.length ? warnings.join('; ') : null;
  return result;
}

async function cmdScan(args) {
  // NON_MUTATING_SCAN_PRD S1 — a scan is an observation; --no-state makes it one.
  if (args.flags['no-state']) {
    const { setStateWritesEnabled } = await import('../src/posture/state-dir.js');
    setStateWritesEnabled(false);
  }
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

  // #21 — --watch : continuous incremental re-scan on file change. Each change
  // re-scans (incrementally) and writes a risk-delta to
  // .agentic-security/watch-status.md that a statusline / /posture poll surfaces
  // inline — so "did my edit add risk?" is answered without a manual re-scan.
  // Blocks until Ctrl-C, like `jest --watch`. Opt-in, so it never affects a
  // normal one-shot scan.
  if (args.flags['watch']) {
    process.env.AGENTIC_SECURITY_INCREMENTAL = '1';
    const { watchProject, computeDelta, persistStatus, renderStatusLine } = await import('../src/posture/watch-mode.js');
    process.stderr.write(`[watch] scanning ${targetAbs} on change — Ctrl-C to stop. Status → .agentic-security/watch-status.md\n`);
    const seed = await runScan(targetAbs, {});
    let prevFindings = seed.scan.findings || [];
    await watchProject(targetAbs, async () => {
      try {
        const { scan } = await runScan(targetAbs, {});
        const curr = scan.findings || [];
        const delta = computeDelta(prevFindings, curr);
        persistStatus(targetAbs, delta);
        process.stderr.write('[watch] ' + renderStatusLine(delta) + '\n');
        prevFindings = curr;
      } catch (e) {
        process.stderr.write(`[watch] rescan failed: ${e.message}\n`);
      }
    });
    return 0; // watchProject blocks until aborted
  }

  // --incremental : reuse taint summaries from prior scans for faster deep mode.
  // #23 — default incremental ON for diff-scoped scans (--pr / --changed-since):
  // that's the cache's designed use (small changed set → its callers), so the
  // PR-native path is fast by default. A full-tree scan stays non-incremental
  // unless explicitly requested (blanket-default flip needs broader validation).
  const _diffScoped = !!(args.flags['pr'] || args.flags['changed-since']);
  if (args.flags['incremental'] || process.env.AGENTIC_SECURITY_INCREMENTAL === '1' || _diffScoped) {
    process.env.AGENTIC_SECURITY_INCREMENTAL = '1';
  }

  // R1 (PRD §5): deep interprocedural taint (IR + field-sensitive, value-context-
  // sensitive dataflow — src/dataflow/) is ON by default for local/interactive CLI
  // scans, bounded by the existing wall-clock budget (AGENTIC_SECURITY_DEEP_TIMEOUT_MS,
  // default 5 min) and function cap (AGENTIC_SECURITY_DEEP_FN_LIMIT, default 5000). It
  // is the engine's strongest analysis and was previously gated off, so the default
  // scan ran pattern/structural-only. Precedence (highest first):
  //   --no-deep / AGENTIC_SECURITY_DEEP=0  → stays off (degrade to structural-only)
  //   --deep    / AGENTIC_SECURITY_DEEP=1  → stays on (even in CI? no — see engine gate)
  //   unset + not in CI                    → default ON here
  //   unset + in CI                        → left unset; the engine keeps deep off in CI
  //                                          unless AGENTIC_SECURITY_DEEP_IN_CI=1
  // The in-process test/bench harnesses call runScan() directly (not this CLI entry),
  // so they are unaffected and remain deterministic regression gates.
  if (args.flags['no-deep']) process.env.AGENTIC_SECURITY_DEEP = '0';
  else if (args.flags['deep']) process.env.AGENTIC_SECURITY_DEEP = '1';
  else if (process.env.AGENTIC_SECURITY_DEEP == null || process.env.AGENTIC_SECURITY_DEEP === '') {
    const inCi = !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI ||
                    process.env.BUILDKITE || process.env.CIRCLECI || process.env.JENKINS_URL);
    if (!inCi) process.env.AGENTIC_SECURITY_DEEP = '1';
  }

  // --pr [ref] : friendlier alias for --changed-since that auto-detects the PR
  // base ref (GitHub/GitLab/Buildkite/Bitbucket env vars) when no value is given.
  let changedSince = args.flags['changed-since'] || null;
  if (args.flags['pr']) {
    const pr = args.flags['pr'];
    changedSince = (typeof pr === 'string' && pr !== 'true') ? pr : (detectBaseline() || 'origin/main');
    process.stderr.write(`[pr-mode] scanning files changed since: ${changedSince}\n`);
  }

  // Finding Provenance (M0/M1) — translate --provenance/--no-provenance/etc.
  // into the env vars engine.js already reads. Must run before runScan()
  // below, same as the --deep/--no-deep wiring above.
  const _provFlags = parseProvenanceFlags(process.argv.slice(2));
  if (_provFlags.warning) console.error(`Warning: ${_provFlags.warning}`);
  if (_provFlags.disabled) process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  process.env.AGENTIC_SECURITY_PROVENANCE_MODE = _provFlags.mode;
  if (_provFlags.since) process.env.AGENTIC_SECURITY_PROVENANCE_SINCE = _provFlags.since;
  if (_provFlags.timeoutMs) process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS = String(_provFlags.timeoutMs);
  if (_provFlags.includeEmail) process.env.AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL = '1';
  if (_provFlags.pseudonymize) process.env.AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS = '1';

  const { scan, meta } = await runScan(target, {
    changedSince,
    onProgress: (p) => {
      if (process.stderr.isTTY) process.stderr.write(`\r[${p.phase}] ${p.current}/${p.total} ${p.file}     `);
    },
  });
  // --require-provenance: flag (never fail) any finding whose provenance
  // isn't resolved, via scanHealth — deliberately independent of the
  // severity-based exit code computed by exitCodeFor() at the end of this
  // function. 'uncommitted' is a legitimate terminal status (the finding is
  // in a file with no git history yet), not an incomplete one.
  if (_provFlags.requireProvenance) {
    // ALL FOUR channels (scanner/CLAUDE.md: findings / secrets / supplyChain /
    // logicVulns). Checking only `scan.findings` made the flag report a clean
    // bill of provenance health for a scan whose SCA and secrets findings had
    // none — and report/index.js's normalizeFindings ships all four to the
    // user as findings, so "every finding" has to mean all four here too.
    const incomplete = [];
    for (const [channel, bucket] of [
      ['findings', scan.findings], ['secrets', scan.secrets],
      ['supplyChain', scan.supplyChain], ['logicVulns', scan.logicVulns],
    ]) {
      for (const f of (bucket || [])) {
        if (!f || typeof f !== 'object') continue;
        if (isProvenanceHealthy(f.findingProvenance)) continue;
        incomplete.push(f.id || f.stableId || `${channel}:${f.name || f.file || f.type || 'entry'}`);
      }
    }
    if (incomplete.length > 0) {
      // Written the way EVERY other scan-health signal is written — a sentence
      // in `conditions[]` plus a `complete` -> `partial` status demotion (see
      // pipeline/scan-health.js's applyFreshness, the same "patch it on from
      // bin/ after the engine already built scanHealth" pattern). The previous
      // version set a bespoke `scanHealth.provenanceIncomplete` key that NO
      // consumer reads: pipeline/assurance-mode.js and
      // posture/compliance-policy.js both read `status`/`conditions[]` only, so
      // --require-provenance changed no behaviour anywhere. The array is still
      // carried, for a consumer that wants the ids, but it is no longer the
      // only trace.
      const condition = `--require-provenance: ${incomplete.length} finding(s) have unresolved provenance`;
      scan.scanHealth = {
        ...(scan.scanHealth || {}),
        conditions: [...(Array.isArray(scan.scanHealth?.conditions) ? scan.scanHealth.conditions : []), condition],
        status: (scan.scanHealth?.status ?? 'complete') === 'complete' ? 'partial' : scan.scanHealth.status,
        provenanceIncomplete: incomplete,
      };
    }
  }

  // The BOM/attestation emitters stamp the producing engine's version into
  // their metadata; carry the real package version so it can never drift.
  if (meta && meta.engineVersion == null) meta.engineVersion = PKG_VERSION;
  if (process.stderr.isTTY) process.stderr.write('\r' + ' '.repeat(80) + '\r');

  const only = args.flags.only;
  if (only) {
    // Four channels exist (scanner/CLAUDE.md): findings (SAST), secrets,
    // supplyChain (SCA), logicVulns (business-logic). --only sast keeps
    // logicVulns (business-logic is source analysis, part of the SAST
    // pillar); --only sca/secrets must also clear it — it's neither SCA
    // nor secrets, and normalizeFindings()/exitCodeFor() both fold it in,
    // so leaving it meant a business-logic finding leaked into a
    // single-pillar scan's output AND its exit code.
    if (only === 'sast') { scan.secrets = []; scan.supplyChain = []; }
    if (only === 'sca')  { scan.findings = []; scan.secrets = []; scan.logicVulns = []; }
    if (only === 'secrets') { scan.findings = []; scan.supplyChain = []; scan.logicVulns = []; }
  }

  // --set-baseline: save current findings as baseline for future --since-baseline filtering
  const baselinePath = statePath(target || '.', 'baseline.json');
  if (args.flags['set-baseline']) {
    const { normalizeFindings } = await import('../src/report/index.js');
    const baselineIds = new Set(normalizeFindings(scan).map(f => f.stableId || f.id));
    fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
    fs.writeFileSync(baselinePath, JSON.stringify({ ids: [...baselineIds], createdAt: new Date().toISOString(), count: baselineIds.size }, null, 2));
    process.stderr.write(`[baseline] saved ${baselineIds.size} findings as baseline\n`);
  }
  // --since-baseline: filter out findings that existed in the saved baseline
  if (args.flags['since-baseline'] && fs.existsSync(baselinePath)) {
    try {
      const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      const baselineSet = new Set(baseline.ids || []);
      const before = scan.findings.length;
      scan.findings = (scan.findings || []).filter(f => !baselineSet.has(f.stableId || f.id));
      process.stderr.write(`[baseline] filtered ${before - scan.findings.length} baseline findings, ${scan.findings.length} new\n`);
    } catch { /* baseline file unreadable, skip */ }
  }

  // R13 (PRD §5): --hide-proven-safe drops findings a flow proof discharged
  // (parameterizer on every path / sanitizer excludes metacharacters) for a
  // clean report. They are kept (demoted) by default so nothing is hidden silently.
  if (args.flags['hide-proven-safe']) {
    const before = (scan.findings || []).length;
    scan.findings = (scan.findings || []).filter(f => !f.provablySafe);
    process.stderr.write(`[proof] hid ${before - (scan.findings || []).length} provably-safe finding(s)\n`);
  }

  // R15 (PRD §5): --secret-history sweeps recent git history for secrets that
  // may have been removed from HEAD but remain recoverable from .git.
  if (args.flags['secret-history']) {
    try {
      const { sweepGitHistory } = await import('../src/posture/secret-history.js');
      const { scanCredentials } = await import('../src/secrets/index.js');
      const depth = parseInt(args.flags['history-depth'] || '50', 10);
      const hist = sweepGitHistory(targetAbs, scanCredentials, { maxCommits: depth });
      if (hist.length) {
        scan.secrets = [...(scan.secrets || []), ...hist];
        process.stderr.write(`[secret-history] ${hist.length} secret(s) found in the last ${depth} commits — rotate even if removed from HEAD\n`);
      } else {
        process.stderr.write(`[secret-history] no secrets found in the last ${depth} commits\n`);
      }
    } catch (e) { if (process.env.AGENTIC_SECURITY_DEBUG === '1') process.stderr.write(`[secret-history] ${e && e.message}\n`); }
  }

  // 0.9.0 Feat-18: --scorecard flag enables OSSF Scorecard enrichment
  if (args.flags['scorecard']) process.env.AGENTIC_SECURITY_SCORECARD = '1';

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
  // Coverage reduction belongs in the ARTIFACT, not only in a log line. A
  // `disable:` that takes effect otherwise produces findings that are simply
  // absent, which is indistinguishable from clean code to whoever reads the
  // report. Recorded whether the suppression was authorised or not — an
  // authorised one still hides results.
  try {
    const _sup = suppressionReport(targetAbs);
    if (_sup) {
      scan.suppressedRules = _sup;
      const _line = renderSuppressionSummary(_sup);
      if (_line) process.stderr.write(`⚠️  agentic-security: ${_line}\n`);
    }
  } catch { /* reporting must never fail a scan */ }

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

  // FR-207: custom rule pack freshness. This is the one freshness leg that
  // cannot be computed inside engine.js -- the pattern-rule DSL only runs
  // here, after scan.scanHealth already exists -- so it's patched on via
  // the same applyFreshness() engine.js uses for the other four legs (see
  // that function's header comment in pipeline/scan-health.js).
  if (scan.scanHealth) {
    try {
      const { applyFreshness } = await import('../src/pipeline/scan-health.js');
      scan.scanHealth = applyFreshness(scan.scanHealth, { customRules: customRulesFreshness(targetAbs) });
    } catch {}
  }

  // EPSS exploit-prediction enrichment (skipped under --no-network / --deterministic).
  // Bumps severity on actively-exploited CVEs so they sort to the top.
  if (!args.flags['no-epss'] && !isDeterministic() && !noNet) {
    try { await enrichWithEPSS(scan); } catch {}
  }

  // Re-run risk-dollars now that both signals it needs are actually
  // available: EPSS (just enriched above — engine.js's own call ran before
  // this, so every finding's epssScore was still unset) and relevanceTier
  // (posture/relevance.js runs last inside runScan/engine.js, so it's
  // populated on `scan.findings` by the time we get here, but wasn't yet
  // when engine.js's own annotateRiskDollars call ran mid-pipeline).
  try {
    const { annotateRiskDollars } = await import('../src/posture/risk-dollars.js');
    annotateRiskDollars(targetAbs, scan.findings || []);
  } catch {}

  // Re-run composite risk for the same reason as annotateRiskDollars above:
  // engine.js's mid-pipeline annotateCompositeRisk calls ran before
  // enrichWithEPSS (just above) had a chance to set f.exploitedNow, so
  // every finding's 'exploited-now-floor:75' boost was computed against a
  // field that was always undefined at the time — an actively-exploited
  // CVE (EPSS percentile >= 0.95) never got its compositeRisk score raised.
  // annotateCompositeRisk is pure/idempotent (only sets compositeRisk*
  // fields, reads everything else), so re-running it here is safe.
  try {
    const { annotateCompositeRisk } = await import('../src/posture/composite-risk.js');
    annotateCompositeRisk(scan.findings || []);
    annotateCompositeRisk(scan.supplyChain || []);
  } catch {}

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

  // R4 — determinism as a contract. Bind the PUBLISHED finding set (the same
  // normalization every report format emits) to the engine version, ruleset
  // version and bundle hash that produced it, via an order-independent digest.
  // Runs after every filter above so it attests what actually ships. Metadata
  // only — a failure here must never fail a scan.
  try {
    const { computeRunAttestation } = await import('../src/posture/attestation.js');
    const { keyProvenance } = await import('../src/posture/integrity.js');
    const { effectiveVersion } = await import('../src/posture/ruleset-version.js');
    scan.attestation = computeRunAttestation({
      findings: normalizeFindings(scan),
      engineVersion: PKG_VERSION,
      rulesetVersion: effectiveVersion(targetAbs).version,
      bundleSha: _bundleSha(),
      root: targetAbs,
      sign: true,
    });
    // P1-3 — a signature is only as meaningful as the key behind it.
    // `env` means whoever set the environment could have signed this;
    // `ephemeral` means the key could not be persisted, so this signature will
    // never verify on any later run. Neither is inferable from the digest.
    if (scan.attestation) scan.attestation.keyProvenance = keyProvenance();
  } catch { /* attestation is metadata; never fail a scan over it */ }

  // R2: Always emit machine-readable artifacts to .agentic-security/.
  await writeMachineOutput(targetAbs, scan, meta, profile, args);

  const includeSuppressed = !!args.flags['include-suppressed'];
  let body;
  if (format === 'json') body = JSON.stringify(toJSON(scan, meta, { includeSuppressed }), null, 2);
  else if (format === 'md' || format === 'markdown') body = toMarkdown(scan, meta);
  else if (format === 'sarif') body = JSON.stringify(toSARIF(scan, meta), null, 2);
  // OSCAL assessment-results. Observations and risks only, never findings — an
  // OSCAL finding is a statement about a control, and a source scan reviews no
  // control catalog. See src/report/oscal.js.
  else if (format === 'oscal') body = JSON.stringify(toOSCAL(scan, meta), null, 2);
  else if (format === 'stix') body = JSON.stringify(toSTIX(scan, meta), null, 2);
  else if (format === 'junit') body = toJUnit(scan, meta);
  else if (format === 'csv')   body = toCSV(scan);
  else if (format === 'html') body = toHTML(scan, meta);
  else if (format === 'cyclonedx' || format === 'sbom') body = JSON.stringify(toCycloneDX(scan, meta), null, 2);
  else if (format === 'spdx')                            body = JSON.stringify(toSPDX(scan, meta), null, 2);
  else if (format === 'vex' || format === 'openvex')     body = JSON.stringify(toVex(scan, meta), null, 2);
  else if (format === 'pbom')                            body = JSON.stringify(toPBOM(scan.fc || {}, meta), null, 2);
  else if (format === 'aibom')                           body = JSON.stringify(buildAIBOM(scan, scan.fc || {}, meta), null, 2);
  else if (format === 'aibom-md')                        body = aibomToMarkdown(buildAIBOM(scan, scan.fc || {}, meta));
  else if (format === 'ship')  body = toShipVerdict(scan, { profile: effProfile });
  else if (format === 'pro')   body = toProTable(scan, { profile: effProfile, columns: args.flags.columns });
  else if (format === 'cli')   body = toCLIByProfile(scan, { profile: effProfile, columns: args.flags.columns, verbose });
  else body = toSummary(scan);

  // --firehose: the verdict/summary views don't list findings — append the full
  // per-finding list (with inline why-it-matters / how-it-fires / fix depth) so
  // "Show ALL findings" actually shows them. Add --verbose for full narration + code.
  if (args.flags.firehose && (!format || format === 'ship' || format === 'summary')) {
    // `provenance` reuses --verbose rather than adding a seventh provenance
    // flag: --verbose already means "print the extra per-finding narration"
    // (explainParts's why/how/fix bodies), and the provenance block is exactly
    // that kind of detail. Before this, explainProvenance()/toCLI's
    // `{provenance}` option had NO production caller at all — it was reachable
    // only from its own unit test, so a feature that was built, reviewed and
    // shipped could never be seen by a user.
    //
    // Gated on provenance actually having run, too: with --no-provenance (or
    // AGENTIC_SECURITY_NO_PROVENANCE=1) every finding carries a `not_available`
    // record, and printing five lines of "we did not look" per finding is noise
    // the operator explicitly opted out of.
    const provenanceOn = !_provFlags.disabled && process.env.AGENTIC_SECURITY_NO_PROVENANCE !== '1';
    body += '\n\n' + toCLI(scan, { verbose, provenance: verbose && provenanceOn });
  }

  // v3 next-gen — supplementary blocks for human-readable formats. These
  // are append-only and do not change the verdict / exit code. The blocks
  // are only meaningful when v3 annotators have run (default scan path).
  if (format === 'cli' || format === 'ship' || format === 'pro' || format === 'md' || format === 'markdown') {
    body += renderV3Blocks(scan, args.flags);
  }

  if (output) await fsp.writeFile(output, body);
  else writeStdout(body + '\n');

  // Persist last scan for /security-fix and /security-report
  const { isSafeStateDir: _isSafeStateDir, stateWritesEnabled: _writesOnScan } = await import('../src/posture/state-dir.js');
  const stateDirPath = stateDir(path.resolve(target));
  // S7 (Stage-0 audit): declared here, not with `const` inside the `if`
  // below — it used to be block-scoped there while recordScan() further
  // down referenced it unconditionally, throwing a ReferenceError on every
  // single scan (silently swallowed by that call's empty catch{}). streak.json
  // — grades, streak days, achievements — never actually persisted through
  // the real CLI as a result, reproduced live before this fix.
  let persistedScan = null;
  if (_writesOnScan() && _isSafeStateDir(stateDirPath)) {
    await fsp.mkdir(stateDirPath, { recursive: true });
    persistedScan = toJSON(scan, meta);
    // Sub-project E, increment 5: the lineage graph gets its OWN artifact
    // file (below), never duplicated inside last-scan.json — a
    // DataFlowGraph v1 document is a separate, potentially large artifact,
    // and embedding it a second time here would bloat the file every other
    // consumer of last-scan.json already reads in full.
    delete persistedScan.lineageGraph;
    // #10 — MTTR: stamp firstSeenAt/lastSeenAt/ageDays from the PREVIOUS scan so
    // every finding carries an age, SLA breaches can be surfaced, and the fix
    // loop can report time-to-clean. Best-effort; skipped under --deterministic
    // so deterministic state stays byte-identical run-to-run.
    if (!args.flags.deterministic) {
      try {
        const { stampFindingTimestamps, buildBaselineMap, renderSlaSummary, fingerprintFinding, computeMTTR } = await import('../src/posture/mttr.js');
        let baselineMap = new Map();
        let prevAll = [];
        try {
          const prev = JSON.parse(await fsp.readFile(path.join(stateDirPath, 'last-scan.json'), 'utf8'));
          baselineMap = buildBaselineMap(prev);
          // The previous scan's own findings already carry firstSeenAt/lastSeenAt
          // from ITS baseline lookup — exactly the shape computeMTTR needs for
          // whichever of them are no longer present now (i.e. were fixed).
          prevAll = [
            ...(prev?.findings || []), ...(prev?.secrets || []),
            ...(prev?.supplyChain || []).filter(s => s.type === 'vulnerable_dep'),
          ];
        } catch { /* first run — empty baseline, everything is firstSeen now */ }
        const now = Date.now();
        stampFindingTimestamps(persistedScan.findings || [], baselineMap, now);
        stampFindingTimestamps(persistedScan.secrets || [], baselineMap, now);
        stampFindingTimestamps((persistedScan.supplyChain || []).filter(s => s.type === 'vulnerable_dep'), baselineMap, now);
        // #10 — MTTR: which of the previous scan's findings are no longer
        // present now (fixed), and how long each took. computeMTTR itself was
        // fully built and tested but had never had a real caller — the module's
        // own comment calls it "true MTTR," distinct from the open-backlog
        // median-age proxy renderSlaSummary already surfaces below.
        const currentFps = new Set([
          ...(persistedScan.findings || []), ...(persistedScan.secrets || []),
          ...(persistedScan.supplyChain || []).filter(s => s.type === 'vulnerable_dep'),
        ].map(fingerprintFinding));
        const removed = prevAll.filter(f => !currentFps.has(fingerprintFinding(f)));
        persistedScan.mttr = computeMTTR(removed);
        // Surface the SLA-breach line on human-readable formats (not JSON/CI pipes).
        const isJson = isMachineFormat(format);
        if (!isJson) {
          const sla = renderSlaSummary(persistedScan.findings || []);
          if (sla) process.stderr.write(`⏰ agentic-security: ${sla}\n`);
          if (persistedScan.mttr.count > 0) {
            process.stderr.write(`✅ agentic-security: ${persistedScan.mttr.count} finding(s) fixed since last scan, median ${Math.round(persistedScan.mttr.medianDays)}d to remediate\n`);
          }
        }
      } catch (e) {
        // MTTR is best-effort — never block a scan write. But a silent catch
        // here previously hid a real, deterministic CI-only failure (the
        // mttr field went missing on every hosted-CI run, never locally, and
        // nothing explained why) for long enough that it shipped several
        // releases undiagnosed. Surface it — never fail the scan on it.
        if (process.env.AGENTIC_SECURITY_MTTR_DEBUG === '1' || process.env.CI || process.env.GITHUB_ACTIONS) {
          process.stderr.write(`agentic-security: MTTR computation failed (best-effort, scan unaffected): ${(e && e.stack) || e}\n`);
        }
      }

      // R5 — report the observed time-to-validated-fix distribution from the
      // fix attempts recorded by `verifyFix`. This is measurement, not
      // estimation: it says nothing until fixes have actually been verified in
      // this project, and it prints nothing when there is nothing measured.
      // Skipped under --deterministic for the same reason MTTR is: the
      // durations are wall-clock and would break byte-identical state.
      try {
        const { fixDurationReport, renderFixDurationSummary } = await import('../src/posture/fix-metrics.js');
        const fixMetrics = fixDurationReport(path.resolve(target));
        if (fixMetrics.attempts > 0) {
          persistedScan.fixMetrics = fixMetrics;
          const isJsonFmt = isMachineFormat(format);
          const line = renderFixDurationSummary(fixMetrics);
          if (!isJsonFmt && line) process.stderr.write(`🔧 agentic-security: ${line}\n`);
        }
      } catch { /* fix metrics are best-effort — never block a scan write */ }
    }
    // #22 — live-secret validation (opt-in, offline-degrading). Label each
    // detected secret live | dead | unknown via a read-only provider "whoami".
    // "This key is LIVE and was committed N commits ago" is the P0 that matters.
    if (args.flags['validate-secrets'] || process.env.AGENTIC_SECURITY_VALIDATE_SECRETS === '1') {
      try {
        const { checkSecretLive } = await import('../src/posture/secret-live-check.js');
        let live = 0;
        for (const s of (persistedScan.secrets || [])) {
          const { verdict, provider } = await checkSecretLive(s);
          s.liveVerdict = verdict;
          if (provider) s.liveProvider = provider;
          if (verdict === 'live') live++;
        }
        if (live > 0) process.stderr.write(`🔴 agentic-security: ${live} LIVE secret(s) validated — rotate immediately (even if already removed from HEAD).\n`);
      } catch { /* best-effort, offline-degrading — never block a scan */ }
    }
    const lastScanBody = JSON.stringify(persistedScan, null, 2);
    await fsp.writeFile(path.join(stateDirPath, 'last-scan.json'), lastScanBody);
    try {
      await fsp.writeFile(path.join(stateDirPath, 'last-scan.json.sig'), _signLastScan(lastScanBody));
    } catch { /* non-fatal — sig file is best-effort */ }
    // Sub-project E, increment 5: persist the lineage graph as its own
    // artifact, mirroring last-scan.json's own write+sign pattern exactly
    // — signLastScan/verifyLastScan are fully generic (an arbitrary string
    // body + an explicit sig-file path, no filename baked in), confirmed by
    // reading posture/integrity.js directly, so no new signing mechanism
    // is introduced. Written only when a graph actually exists — an
    // ordinary scan (AGENTIC_SECURITY_LINEAGE_DEEP unset) writes nothing
    // new here at all.
    if (scan.lineageGraph) {
      try {
        const lineageBody = JSON.stringify(scan.lineageGraph, null, 2);
        await fsp.writeFile(path.join(stateDirPath, 'lineage-graph.json'), lineageBody);
        try {
          await fsp.writeFile(path.join(stateDirPath, 'lineage-graph.json.sig'), _signLastScan(lineageBody));
        } catch { /* non-fatal — sig file is best-effort, same precedent as last-scan.json.sig above */ }
      } catch { /* non-fatal — the lineage artifact write is best-effort and must never block a scan */ }
    }
  } else {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') process.stderr.write(`[agentic-security] refusing to write state at ${stateDirPath} — no project marker in ${path.resolve(target)}\n`);
  }

  // 0.14.0 — update streak / achievements after every full scan. Suppress
  // streak side effects when the user only wants raw JSON output (CI piping).
  // Gated on `persistedScan !== null` (i.e. the same _writesOnScan() &&
  // _isSafeStateDir() condition above) — recordScan()'s own isSafeStateDir
  // check alone does not know about --no-state / AGENTIC_SECURITY_NO_STATE,
  // so without this a "read-only, mutates nothing" scan would still write
  // streak.json. This was accidentally masked before the persistedScan
  // scoping fix (recordScan was never reached at all, for the wrong reason);
  // fixing that reachability bug required adding this guard explicitly.
  try {
    const streak = persistedScan !== null ? recordScan(stateDirPath, persistedScan) : null;
    // Print celebration / streak line to stderr so it doesn't pollute --format json
    if (streak && process.stderr.isTTY && !isMachineFormat(format)) {
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

  // R4 — same run attestation cmdScan attaches, computed here too so
  // findings.json (the actual CI evidence artifact) carries the same
  // tamper-evidence digest 'agentic-security scan' does, rather than
  // always shipping attestation: null. Runs after every filter above, so
  // it attests what actually ships. Metadata only — never fails the scan.
  try {
    const { computeRunAttestation } = await import('../src/posture/attestation.js');
    const { keyProvenance } = await import('../src/posture/integrity.js');
    const { effectiveVersion } = await import('../src/posture/ruleset-version.js');
    scan.attestation = computeRunAttestation({
      findings: normalizeFindings(scan),
      engineVersion: PKG_VERSION,
      rulesetVersion: effectiveVersion(targetAbs).version,
      bundleSha: _bundleSha(),
      root: targetAbs,
      sign: true,
    });
    if (scan.attestation) scan.attestation.keyProvenance = keyProvenance();
  } catch { /* attestation is metadata; never fail a scan over it */ }

  // Persist the three CI artifacts — but a refusal to write must NEVER skip
  // the --fail-on evaluation below. S1 (Stage-0 audit, 2026): this used to be
  // a bare `return;` inside the write-guard, so `cmdCi` returned `undefined`
  // and `process.exit(await cmdCi(args))` became `process.exit(undefined)`,
  // which Node treats as exit 0 — a CI pipeline reading only $? would see a
  // passing build whose findings were never evaluated against --fail-on at
  // all. The write and the gate are orthogonal: "we couldn't persist
  // artifacts" is not evidence about "the scan is clean."
  const stateDirPath = stateDir(targetAbs);
  const { isSafeStateDir: _isSafeCi, stateWritesEnabled: _writesOnCi } = await import('../src/posture/state-dir.js');
  const _canWriteCi = _writesOnCi() && _isSafeCi(stateDirPath);
  if (!_canWriteCi) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') process.stderr.write(`[agentic-security] refusing to write CI artifacts at ${stateDirPath} — no project marker\n`);
  } else {
    await fsp.mkdir(stateDirPath, { recursive: true });
    await fsp.writeFile(path.join(stateDirPath, 'findings.json'),
      JSON.stringify(toJSON(scan, meta), null, 2));
    await fsp.writeFile(path.join(stateDirPath, 'findings.sarif'),
      JSON.stringify(toSARIF(scan, meta), null, 2));
    await fsp.writeFile(path.join(stateDirPath, 'findings.junit.xml'),
      toJUnit(scan, meta));
  }

  const scanCode = exitCodeFor(scan);
  const findings = normalizeFindings(scan);
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
  // FR-206: "reports show both finding count and scan-health status." A
  // 0-finding scan-exit is not the same claim as "the scan actually
  // finished cleanly" — an annotator error, a file timeout, or a skipped
  // analyzer already demotes scan.scanHealth.status to 'partial'
  // (scan-health.js), but until this line nothing in `ci`'s own printed
  // report ever surfaced it, so a broken analyzer could pass CI silently.
  // This is a REPORT fix, not a gate-policy change: whether an incomplete
  // scan should itself FAIL the build regardless of --fail-on is FR-204's
  // job (assurance modes advisory/standard/strict), not yet implemented —
  // deliberately not conflated with this fix.
  const _health = scan.scanHealth;
  const _healthLine = (_health && _health.status && _health.status !== 'complete')
    ? `[ci] ⚠ scan-health=${_health.status} — ${(_health.conditions || [])[0] || 'analysis did not complete cleanly'}${(_health.conditions || []).length > 1 ? ` (+${_health.conditions.length - 1} more)` : ''}\n`
    : `[ci] scan-health=${_health && _health.status ? _health.status : 'unknown'}\n`;
  process.stderr.write(
    `[ci] ${findings.length} findings — ${sev.critical} critical · ${sev.high} high · ${sev.medium} medium · ${sev.low} low\n` +
    _healthLine +
    (_canWriteCi
      ? `[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}\n`
      : `[ci] artifacts: NOT written (state writes refused — set AGENTIC_SECURITY_DEBUG=1 for the reason)\n`) +
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
  // FR-204: assurance modes. Runs ALONGSIDE --fail-on and --policy, same
  // precedent as FR-SDLC-9's policy gate above — any of the three can fail
  // the build independently. `standard` (the default) never fails here;
  // `strict` fails the build when the scan itself was not fully complete,
  // regardless of how few/no findings resulted from the incomplete run.
  const { evaluateAssuranceMode, ASSURANCE_MODES, DEFAULT_ASSURANCE_MODE } = await import('../src/pipeline/assurance-mode.js');
  const assuranceMode = args.flags.assurance || DEFAULT_ASSURANCE_MODE;
  if (!ASSURANCE_MODES.includes(assuranceMode)) {
    console.error(`[ci] --assurance must be one of: ${ASSURANCE_MODES.join('|')} (got '${assuranceMode}')`);
    return 1;
  }
  const assuranceVerdict = evaluateAssuranceMode(assuranceMode, scan.scanHealth, findings);
  if (!assuranceVerdict.ok) {
    console.error(`[ci] assurance gate FAILED (mode=${assuranceMode}): ${assuranceVerdict.reason}`);
    return 1;
  }
  if (assuranceMode === 'strict') process.stderr.write(`[ci] assurance gate PASSED (mode=strict)\n`);
  // R24 (PRD §5): PR-native net-new gate. With --fail-on-new and a baseline
  // ref, block ONLY on findings this PR INTRODUCED (vs the base ref), never on
  // the pre-existing backlog — the posture teams actually leave enabled.
  if (args.flags['fail-on-new']) {
    const baseRef = baseline;
    if (!baseRef) {
      process.stderr.write('[ci] --fail-on-new requires a baseline ref (--baseline <ref> or a CI base-branch env var)\n');
      return 1;
    }
    try {
      const { computePrDelta, netNewGate } = await import('../src/pr-delta.js');
      const delta = await computePrDelta(target, { baseRef });
      const gate = netNewGate(delta, failOn);
      process.stderr.write(
        `[ci] net-new vs ${baseRef}: +${delta.introduced.length} introduced · -${delta.resolved.length} resolved · ${delta.persistent.length} pre-existing (not gated)\n` +
        `[ci] net-new gate fail-on=${failOn} → ${gate.fail ? 'FAIL' : 'pass'}${gate.blocked.length ? ' (' + gate.blocked.length + ' blocking)' : ''}\n`);
      for (const f of gate.blocked.slice(0, 20)) process.stderr.write(`  + [${(f.severity || '').toUpperCase()}] ${f.vuln || f.type} ${f.file}:${f.line}\n`);
      return gate.fail ? 1 : 0;
    } catch (e) {
      process.stderr.write(`[ci] net-new gate error: ${(e && e.message) || e} — falling back to full --fail-on gate\n`);
      // Fall through to the full gate rather than passing silently.
    }
  }
  return ciExitCode(scanCode, failOn);
}

// /accept --finding <id> --reason "..."  (vibecoder soft 30-day suppression)
async function cmdAccept(args) {
  const target = path.resolve(args._[1] || '.');
  const id = args.flags.finding;
  if (!id) { console.error('--finding <id> required'); return 4; }
  const reason = args.flags.reason || 'vibecoded for now';
  const lastScanPath = statePath(target, 'findings.json');
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
  const lastScanPath = statePath(target, 'findings.json');
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
    // FR-907: longitudinal production feedback — aggregates 5 already-
    // separate mechanisms (user suppression, accepted risk, invalid
    // finding, fixed finding, verification outcome) into one view, rather
    // than requiring an operator to check 5 different files by hand.
    const { productionFeedbackReport, renderProductionFeedbackSummary } = await import('../src/posture/production-feedback.js');
    const feedback = productionFeedbackReport(target, { sinceDays: days });
    const feedbackSummary = renderProductionFeedbackSummary(feedback);
    if (feedbackSummary) {
      console.log('');
      console.log(feedbackSummary);
    }
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
  else writeStdout(body + '\n');
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
  const cacheDir = statePath(root, 'llm-cache');
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
  const lastScanPath = statePath(scanRoot, 'last-scan.json');
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
  const stateDirPath = stateDir(scanRoot);
  if (!fs.existsSync(stateDirPath)) {
    console.log(`No state to reset at ${stateDirPath}`);
    return 0;
  }
  // FR-703 (assurance-hardening PRD): registry-driven, not enumeration-
  // driven. The registry (src/posture/artifact-registry.js) is built from an
  // audit of every state-writing call site in src/ and bin/, not a
  // hand-maintained list that drifts as new artifacts are added — see that
  // module's header for the classification rules (generated vs
  // operator-config) and the corrections it made to this project's own PRD
  // evidence table along the way.
  const GENERATED = new Set(listGeneratedArtifacts().map(a => a.name));
  const keep = new Set((args.flags.keep || '').split(',').filter(Boolean));
  // FR-702: `--expired` narrows the reset to only artifacts that are past
  // their retention-class TTL (cache/scan/evidence/ticket/backup — see
  // posture/retention-policy.js), rather than every registered generated
  // artifact. Reuses this same command's existing confirm/keep/preserve
  // machinery — a second, parallel deletion pathway would be a second
  // place to get path-safety wrong.
  let targets;
  if (args.flags.expired) {
    const { findExpiredArtifacts } = await import('../src/posture/retention-policy.js');
    targets = findExpiredArtifacts(scanRoot)
      .filter(a => !keep.has(a.name))
      .map(a => ({ name: a.name, dir: a.isDir, ageDays: a.ageDays, ttlDays: a.ttlDays, retentionClass: a.retentionClass }));
  } else {
    targets = [];
    for (const entry of await fsp.readdir(stateDirPath, { withFileTypes: true })) {
      if (keep.has(entry.name)) continue;
      if (GENERATED.has(entry.name)) {
        targets.push({ name: entry.name, dir: entry.isDirectory() });
      }
    }
  }
  // FR-707: an artifact under an active legal hold is pulled OUT of the
  // deletion targets regardless of mode — a hold must protect against a
  // PLAIN `reset --yes` too (which otherwise deletes every registered
  // 'generated' artifact unconditionally), not just `--expired`, which
  // retention-policy.js's own findExpiredArtifacts already excludes on its
  // own as a second, defense-in-depth enforcement of the same guarantee.
  const { loadLegalHolds, isUnderHold } = await import('../src/posture/legal-hold.js');
  const holds = loadLegalHolds(scanRoot);
  const heldDetail = [];
  targets = targets.filter(t => {
    const hold = isUnderHold(t.name, holds);
    if (!hold) return true;
    heldDetail.push({ name: t.name, dir: !!t.dir, reason: `active legal hold (owner: ${hold.owner}, reason: ${hold.reason})` });
    return false;
  });
  if (!targets.length) {
    console.log(args.flags.expired ? `Nothing expired under ${stateDirPath}.` : `Nothing to reset under ${stateDirPath}.`);
    if (heldDetail.length) {
      console.log(`Preserving ${heldDetail.length} artifact(s) under active legal hold: ${heldDetail.map(h => h.name).sort().join(', ')}`);
    }
    return 0;
  }
  console.log(`agentic-security reset${args.flags.expired ? ' --expired' : ''} — will remove from ${stateDirPath}:`);
  for (const t of targets) {
    const ttlNote = args.flags.expired ? `  (${t.retentionClass}, ${t.ageDays.toFixed(1)}d old, ttl ${t.ttlDays}d)` : '';
    console.log(`  ${t.name}${t.dir ? '/' : ''}${ttlNote}`);
  }
  console.log('');
  // FR-703: report what is ACTUALLY present and being left alone, rather
  // than a hardcoded 5-name string that drifted behind the real config
  // surface (risk-config.yml, profile.yml, suppressions.yml, and others were
  // silently omitted from the old message even though they were already
  // correctly never wiped).
  const targetNames = new Set(targets.map(t => t.name));
  const heldNames = new Set(heldDetail.map(h => h.name));
  const preserved = heldDetail.map(h => h.name + (h.dir ? '/' : ''));
  const preservedDetail = heldDetail.map(h => ({ name: h.name, reason: h.reason }));
  for (const entry of await fsp.readdir(stateDirPath, { withFileTypes: true })) {
    if (keep.has(entry.name) || targetNames.has(entry.name) || heldNames.has(entry.name)) continue;
    if (!args.flags.expired && GENERATED.has(entry.name)) continue;
    preserved.push(entry.name + (entry.isDirectory() ? '/' : ''));
    preservedDetail.push({
      name: entry.name,
      reason: args.flags.expired && GENERATED.has(entry.name)
        ? 'generated artifact still within its retention TTL'
        : 'operator-authored configuration',
    });
  }
  if (preserved.length) {
    console.log(args.flags.expired
      ? `Preserving operator-authored config and generated artifacts still within their TTL: ${preserved.sort().join(', ')}`
      : `Preserving operator-authored config: ${preserved.sort().join(', ')}`);
  }
  // FR-706: every reset invocation — dry-run or applied — leaves a durable,
  // structured record of what it planned, deleted, preserved, or failed to
  // delete, not just console output that vanishes once the terminal
  // scrolls past it.
  const { buildDeletionReport, writeDeletionReport } = await import('../src/posture/state-lifecycle-report.js');
  const mode = args.flags.expired ? 'reset --expired' : 'reset';
  if (!args.flags.yes) {
    console.log('');
    console.log('Pass --yes to proceed (or --keep <name,name> to spare specific items).');
    writeDeletionReport(scanRoot, buildDeletionReport({
      mode, dryRun: true, root: scanRoot,
      items: targets.map(t => ({
        name: t.name, dir: !!t.dir, status: 'planned',
        retentionClass: t.retentionClass || null, ageDays: t.ageDays ?? null, ttlDays: t.ttlDays ?? null,
      })),
      preserved: preservedDetail,
    }));
    return 0;
  }
  const outcomes = [];
  for (const t of targets) {
    const p = path.join(stateDirPath, t.name);
    const base = { name: t.name, dir: !!t.dir, retentionClass: t.retentionClass || null, ageDays: t.ageDays ?? null, ttlDays: t.ttlDays ?? null };
    try {
      if (t.dir) await fsp.rm(p, { recursive: true, force: true });
      else await fsp.rm(p, { force: true });
      outcomes.push({ ...base, status: 'deleted' });
    } catch (e) {
      console.error(`reset: failed to remove ${p}: ${e.message}`);
      outcomes.push({ ...base, status: 'failed', error: e.message });
    }
  }
  const failedCount = outcomes.filter(o => o.status === 'failed').length;
  console.log(`Reset ${outcomes.length - failedCount} item(s)${failedCount ? `, ${failedCount} failed` : ''}. Operator-authored config preserved.`);
  const reportPath = writeDeletionReport(scanRoot, buildDeletionReport({
    mode, dryRun: false, root: scanRoot, items: outcomes, preserved: preservedDetail,
  }));
  if (reportPath) console.log(`Deletion report: ${path.relative(scanRoot, reportPath)}`);
  return failedCount ? 1 : 0;
}

// `agentic-security export --out <dir> [--root <path>]`
//
// FR-706 (assurance-hardening PRD): the "exported" half of "operators can
// prove what was exported, deleted, retained, or failed." Copies every
// CURRENTLY-PRESENT registered artifact — generated AND operator-config —
// from .agentic-security/ into an operator-chosen destination, alongside a
// manifest naming exactly what was copied (with a content hash for files)
// and what failed. Unlike `reset`, classification does not gate inclusion:
// an export is a snapshot for the operator's own records, migration, or
// legal-preservation purposes, not a deletion decision.
async function cmdExport(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const stateDirPath = stateDir(scanRoot);
  if (!fs.existsSync(stateDirPath)) {
    console.log(`No state to export at ${stateDirPath}`);
    return 0;
  }
  if (!args.flags.out) {
    console.error('export: --out <dir> is required.');
    return 2;
  }
  const outDir = path.resolve(args.flags.out);
  await fsp.mkdir(outDir, { recursive: true });

  const { ARTIFACT_REGISTRY } = await import('../src/posture/artifact-registry.js');
  const { buildExportReport, writeExportReport } = await import('../src/posture/state-lifecycle-report.js');
  const { createHash } = await import('node:crypto');
  const present = new Set((await fsp.readdir(stateDirPath, { withFileTypes: true })).map(e => e.name));

  const items = [];
  for (const artifact of ARTIFACT_REGISTRY) {
    if (!present.has(artifact.name)) continue;
    const src = path.join(stateDirPath, artifact.name);
    const dest = path.join(outDir, artifact.name);
    try {
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      if (artifact.kind === 'dir') {
        await fsp.cp(src, dest, { recursive: true });
        items.push({ name: artifact.name, classification: artifact.classification, retentionClass: artifact.retentionClass || null, status: 'exported', sha256: null });
      } else {
        await fsp.copyFile(src, dest);
        const sha256 = createHash('sha256').update(fs.readFileSync(src)).digest('hex');
        items.push({ name: artifact.name, classification: artifact.classification, retentionClass: artifact.retentionClass || null, status: 'exported', sha256 });
      }
    } catch (e) {
      items.push({ name: artifact.name, classification: artifact.classification, retentionClass: artifact.retentionClass || null, status: 'failed', error: e.message });
    }
  }

  const report = buildExportReport({ root: scanRoot, outDir, items });
  const manifestPath = path.join(outDir, 'export-manifest.json');
  await fsp.writeFile(manifestPath, JSON.stringify(report, null, 2) + '\n');
  writeExportReport(scanRoot, report); // last-action record kept under .agentic-security/ too, same as deletion-report.json

  const failedCount = items.filter(i => i.status === 'failed').length;
  console.log(`Exported ${items.length - failedCount} artifact(s) to ${outDir}${failedCount ? `, ${failedCount} failed` : ''}.`);
  console.log(`Manifest: ${manifestPath}`);
  return failedCount ? 1 : 0;
}

// `agentic-security legal-hold add --artifact <name> --owner <id> --reason <text> [--expires <date>]`
// `agentic-security legal-hold remove --artifact <name>`
// `agentic-security legal-hold list [--all]`
//
// FR-707 (assurance-hardening PRD): identity-bound (--owner), reasoned
// (--reason), time-bounded where applicable (--expires is optional — an
// indefinite hold has no end date), and auditable (`list` reads back
// exactly what was recorded). See posture/legal-hold.js for the full
// design rationale and how this is enforced inside `cmdReset`.
async function cmdLegalHold(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const sub = args._[1];
  const { addLegalHold, removeLegalHold, listLegalHolds } = await import('../src/posture/legal-hold.js');

  if (sub === 'add') {
    const result = addLegalHold(scanRoot, {
      artifact: args.flags.artifact, owner: args.flags.owner, reason: args.flags.reason, expires_at: args.flags.expires,
    });
    if (!result.ok) { console.error(`legal-hold add: ${result.reason}`); return 2; }
    console.log(`Legal hold placed on "${result.hold.artifact}" (owner: ${result.hold.owner}${result.hold.expires_at ? `, expires ${result.hold.expires_at}` : ', indefinite'}).`);
    return 0;
  }
  if (sub === 'remove') {
    if (!args.flags.artifact) { console.error('legal-hold remove: --artifact <name> is required.'); return 2; }
    const removedCount = removeLegalHold(scanRoot, args.flags.artifact);
    console.log(removedCount ? `Removed ${removedCount} hold(s) on "${args.flags.artifact}".` : `No hold found on "${args.flags.artifact}".`);
    return 0;
  }
  if (sub === 'list' || !sub) {
    const holds = listLegalHolds(scanRoot, { includeExpired: !!args.flags.all });
    if (!holds.length) { console.log(args.flags.all ? 'No legal holds recorded (ever).' : 'No active legal holds.'); return 0; }
    for (const h of holds) {
      console.log(`  ${h.artifact}  owner=${h.owner}  reason="${h.reason}"  expires=${h.expires_at || 'never'}  created=${h.created_at}`);
    }
    return 0;
  }
  console.error(`legal-hold: unknown subcommand "${sub}" (expected add|remove|list).`);
  return 2;
}

// `agentic-security calibration-feedback record --finding-id <id> --outcome accepted-risk|realized-incident [--note <text>]`
// `agentic-security calibration-report`
//
// FR-806 (assurance-hardening PRD): genuinely opt-in — nothing here is ever
// written by a scan. See posture/calibration-feedback.js for the full
// scoping rationale (why "aggregated" means within-installation, why the
// record snapshots only prediction signals and never file/line/vuln text).
async function cmdCalibrationFeedback(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const sub = args._[1];
  const { recordCalibrationFeedback, OUTCOMES } = await import('../src/posture/calibration-feedback.js');

  if (sub === 'record') {
    const result = recordCalibrationFeedback(scanRoot, {
      findingId: args.flags['finding-id'], outcome: args.flags.outcome, note: args.flags.note,
    });
    if (!result.ok) { console.error(`calibration-feedback record: ${result.reason}`); return 2; }
    // The persisted record.findingId is privacy-safe (a hash), not the
    // caller's own input -- echo back what the operator actually typed.
    console.log(`Recorded "${result.record.outcome}" for finding ${args.flags['finding-id']}.`);
    return 0;
  }
  console.error(`calibration-feedback: unknown subcommand "${sub}" (expected record --finding-id <id> --outcome ${OUTCOMES.join('|')} [--note <text>]).`);
  return 2;
}

async function cmdCalibrationReport(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const { buildCalibrationReport, renderCalibrationReportSummary } = await import('../src/posture/calibration-feedback.js');
  const report = buildCalibrationReport(scanRoot);
  if (args.flags.format === 'json') { writeStdout(JSON.stringify(report, null, 2) + '\n'); return 0; }
  const summary = renderCalibrationReportSummary(report);
  console.log(summary || 'No calibration feedback recorded yet — this is opt-in; see `calibration-feedback record --help`.');
  return 0;
}

// `agentic-security rule-synth [--dry-run] [--threshold N]`
//
// FR-LEARN-6: read triage-feedback.json, group repeated FP verdicts by
// (family, dir prefix), and propose a suppression YAML when ≥ threshold
// (default 5) verdicts cluster. Writes to .agentic-security/rules-proposed/.
// Languages the Layer-1 IR parses. Anything else cannot be partitioned into a
// call-graph focus area, so feeding it to a hunter would spend tokens on files
// the confirmation gate can never corroborate.
const HUNT_EXTS = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|go|php|rb)$/i;
const HUNT_IGNORE = ['node_modules/**', '.git/**', 'dist/**', 'build/**', 'vendor/**', '**/.agentic-security/**'];
const HUNT_MAX_FILES = 2000;

async function cmdHunt(args) {
  const scanRoot = path.resolve(args.flags.root || args._[1] || '.');
  const { listFiles } = await import('../src/util/glob.js');
  const { buildProjectIR } = await import('../src/ir/index.js');
  const { runDiscovery } = await import('../src/discovery/index.js');
  const { LENSES } = await import('../src/discovery/lenses.js');

  const rels = (await listFiles(scanRoot, { ignore: HUNT_IGNORE })).filter(f => HUNT_EXTS.test(f));
  if (rels.length > HUNT_MAX_FILES) {
    console.error(`agentic-security: ${rels.length} source files exceeds the ${HUNT_MAX_FILES}-file hunt cap.`);
    console.error('Narrow the scope with --root <subdir>. Discovery is token-expensive and');
    console.error('unbounded fan-out on a large repository is the wrong default.');
    return 2;
  }

  const fileContents = {};
  for (const rel of rels) {
    try { fileContents[rel] = fs.readFileSync(path.join(scanRoot, rel), 'utf8'); } catch { /* unreadable — skip */ }
  }

  const { perFile, callGraph } = buildProjectIR(fileContents);

  // Prior scan and triage verdicts feed the judge so a hunt does not re-report
  // what the rule engine already found or what a human already dismissed.
  let priorScan = null, triageFeedback = null;
  try { priorScan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); } catch {}
  try { triageFeedback = JSON.parse(fs.readFileSync(statePath(scanRoot, 'triage-feedback.json'), 'utf8')); } catch {}

  const lenses = args.flags.lens ? String(args.flags.lens).split(',').map(s => s.trim()).filter(Boolean) : undefined;
  const intFlag = (name) => (args.flags[name] ? parseInt(args.flags[name], 10) : undefined);
  const numFlag = (name) => (args.flags[name] ? Number(args.flags[name]) : undefined);
  const report = await runDiscovery(
    { perFileIR: perFile, callGraph, fileContents, priorScan, triageFeedback },
    {
      lenses,
      maxAreas: intFlag('max-areas'),
      // PRD Phase 0 / C3. Defaults live in discovery/index.js so the library is
      // bounded even when driven by something other than this CLI.
      maxLlmCalls: intFlag('max-llm-calls'),
      maxWallMs: intFlag('max-wall-ms'),
      maxCandidates: intFlag('max-candidates'),
      maxCostUsd: numFlag('max-cost-usd'),
      // PRD C4 — persist and consult cross-run memory.
      scanRoot: args.flags['no-memory'] ? undefined : scanRoot,
      // PRD C2 — a comma-separated endpoint list turns on consensus.
      endpoints: args.flags.endpoints,
      costPerCallUsd: numFlag('cost-per-call-usd'),
    },
  );

  const c = report.coverage;
  console.log('');
  console.log(`Discovery — ${rels.length} file(s), ${c.areasPlanned} focus area(s), ${c.lensesPerArea} lens(es) each`);
  console.log(`  areas hunted: ${c.areasHunted}/${c.areasPlanned} (fully: ${c.areasFullyHunted})   degraded runs: ${c.degradedRuns}/${report.runs.length}`);
  console.log(`  budget: ${c.llmCalls}/${c.maxLlmCalls} LLM calls${c.budgetExhausted ? '  ← EXHAUSTED, run is incomplete' : ''}` +
    `${c.candidatesCapped ? `   ${c.candidatesCapped} candidate(s) capped` : ''}` +
    `${c.callsPerFinding !== null && c.callsPerFinding !== undefined ? `   ${c.callsPerFinding} calls/finding` : ''}`);
  if (c.priorRuns !== null && c.priorRuns !== undefined) {
    console.log(`  memory: ${c.priorRuns} prior run(s)` +
      `${c.rememberedRefutals ? `, ${c.rememberedRefutals} candidate(s) skipped as already refuted` : ''}`);
    if (c.nextWave?.summary) console.log(`  next wave: ${c.nextWave.summary}`);
  }
  console.log(`  confirmation: ${JSON.stringify(c.confirmedByTier)}   panels: ${c.panelsRun} (undecided ${c.undecidedPanels})`);
  console.log('');

  if (report.fresh.length === 0) {
    console.log('No new candidates survived confirmation and refutation.');
  } else {
    console.log(`${report.fresh.length} new candidate finding(s):`);
    for (const f of report.fresh) {
      console.log(`  [${f.severity}] ${f.file}:${f.line}  ${f.vuln}`);
      console.log(`      lens=${f.discovery.lens} confirmation=${f.discovery.confirmation?.tier || 'unknown'}`);
    }
  }
  if (report.duplicates.length || report.suppressed.length || report.refutedCandidates.length) {
    console.log('');
    console.log(`  (${report.duplicates.length} already known, ${report.suppressed.length} previously marked false positive, ` +
      `${report.refutedCandidates.length} refuted by the panel)`);
  }

  // PRD C5 — variant analysis. A confirmed finding is rarely alone: the same
  // root cause is usually copy-pasted, and the siblings often do not trip a
  // rule. sweepRootCauses already does this with exact accounting for scan
  // findings; discovery findings simply never reached it until now.
  if (report.fresh.length && !args.flags['no-variants']) {
    try {
      const { sweepRootCauses, formatSweepLedger } = await import('../src/posture/root-cause-sweep.js');
      const sweep = sweepRootCauses(report.fresh, fileContents, { confirmedOnly: false });
      const ledger = formatSweepLedger(sweep);
      if (ledger) {
        console.log('');
        console.log('Variant sweep (siblings of the findings above):');
        console.log(`  ${ledger}`);
      }
    } catch { /* the sweep is additive; never let it sink the report */ }
  }

  // Degradation is part of the output. A half-failed hunt must never read as a
  // clean one, so every reason is printed rather than summarised away.
  if (c.reasons.length) {
    console.log('');
    console.log('Coverage gaps:');
    for (const r of c.reasons) console.log(`  · ${r}`);
  }
  if (report.runs.length && c.degradedRuns === report.runs.length) {
    console.log('');
    console.log('EVERY hunter run degraded — this result says nothing about the code.');
    console.log('Set AGENTIC_SECURITY_LLM_ENDPOINT to enable discovery.');
  }

  // Advisory by design: discovery never gates. Exit 0 unless the scope was bad.
  console.log('');
  console.log(`Lenses available: ${LENSES.map(l => l.key).join(', ')}  (--lens a,b to narrow)`);
  return 0;
}

// PRD D2 — emit signed, per-finding evidence bundles, and verify them.
//
// `attest` needs our private key. `verify-attestation` needs ONLY a public key,
// which is the entire point: a buyer or auditor checks the artefact without ever
// having had access to anything of ours.
/**
 * `compliance` — framework assessment from the CLI.
 *
 * Reads the LAST SCAN rather than running a new one. A compliance answer is a
 * statement about a scan that happened, and silently re-scanning here would
 * make the number depend on when you asked rather than on what was measured —
 * the same class of confusion as a benchmark that mutates its own corpus. If
 * there is no scan to read, this says so and exits non-zero instead of
 * assessing an empty project, which would report controls as satisfied on the
 * strength of having looked at nothing.
 */
async function cmdCompliance(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const fmt = String(args.flags.format || 'cli');
  const {
    assessPrivacyFramework, PRIVACY_FRAMEWORK_ID, BUCKETS,
  } = await import('../src/posture/privacy-framework.js');
  const { listFrameworks, loadFramework, evaluateFramework, renderWalkthrough } =
    await import('../src/posture/auditor-walkthrough.js');

  if (args.flags.list) {
    const fws = listFrameworks(scanRoot);
    if (fmt === 'json') { writeStdout(JSON.stringify(fws, null, 2) + '\n'); return 0; }
    for (const f of fws) console.log(`  ${f.id.padEnd(20)} ${f.name}  [${f.source}]`);
    return 0;
  }

  let scan;
  try { scan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); }
  catch {
    console.error('No .agentic-security/last-scan.json — run `agentic-security scan .` first.');
    console.error('Refusing to assess an unscanned project: every control would report as');
    console.error('unassessed, which is correct but useless, and one flag away from looking clean.');
    return 2;
  }
  // The engine records this two ways depending on the emit path; take either.
  scan.filesScanned = scan._scanMeta?.filesScanned ?? scan.scanned?.files ?? 0;

  // `--report <fw>` is accepted as a synonym for `--walkthrough <fw>`: the
  // slash-command surface has always spelled it that way, and it previously
  // reached the frameworks only through an inlined node call in commands/
  // rather than through this CLI. One code path, two spellings.
  const wt = args.flags.walkthrough || args.flags.report;
  if (wt && wt !== true) {
    const fw = loadFramework(scanRoot, String(wt));
    if (!fw) {
      console.error(`Unknown framework "${wt}". Try --list.`);
      return 2;
    }
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    if (fmt === 'oscal') {
      const { toOSCALCompliance, complianceRowsFromEvaluation } = await import('../src/report/oscal.js');
      writeStdout(JSON.stringify(
        toOSCALCompliance(fw, complianceRowsFromEvaluation(evaluation), { startedAt: scan._scanMeta?.startedAt }),
        null, 2) + '\n');
      return 0;
    }
    if (fmt === 'json') { writeStdout(JSON.stringify(evaluation, null, 2) + '\n'); return 0; }
    console.log(renderWalkthrough(fw, evaluation, {}));
    return 0;
  }

  // Default mode is --privacy: it is the only framework with a remediation
  // layer, so it is the only one where a CLI exit code means anything.
  const r = assessPrivacyFramework(scanRoot, scan);
  if (!r) { console.error(`Framework ${PRIVACY_FRAMEWORK_ID} could not be loaded.`); return 2; }

  const gapsOnly = !!args.flags.gap;
  if (fmt === 'oscal') {
    // The privacy assessment's own bucket model, not evaluateFramework's — see
    // complianceRowsFromPrivacy for why `engine-gap` must not become a control
    // failure. `--gap` is deliberately NOT applied here: an OSCAL document that
    // silently omitted the satisfied controls would understate what was
    // reviewed, and reviewed-controls would then disagree with the findings.
    const { toOSCALCompliance, complianceRowsFromPrivacy } = await import('../src/report/oscal.js');
    const fwMeta = loadFramework(scanRoot, PRIVACY_FRAMEWORK_ID) || { id: PRIVACY_FRAMEWORK_ID, name: r.frameworkName };
    writeStdout(JSON.stringify(
      toOSCALCompliance(fwMeta, complianceRowsFromPrivacy(r), { startedAt: scan._scanMeta?.startedAt }),
      null, 2) + '\n');
    return args.flags['fail-on'] === 'gap' && r.summary.gap > 0 ? 1 : 0;
  }
  if (fmt === 'json') {
    writeStdout(JSON.stringify(gapsOnly ? { ...r, controls: r.controls.filter(c => c.bucket === 'gap') } : r, null, 2) + '\n');
  } else if (fmt === 'md') {
    console.log(fs.readFileSync(statePath(scanRoot, 'privacy-framework.md'), 'utf8'));
  } else {
    console.log(`\n${r.frameworkName}\n`);
    console.log(`  ${r.interpretation}\n`);
    for (const b of BUCKETS) {
      const rows = r.controls.filter(c => c.bucket === b);
      if (!rows.length || (gapsOnly && b !== 'gap')) continue;
      console.log(`  ${b} (${rows.length})`);
      for (const c of rows) {
        console.log(`    ${c.id.padEnd(11)} ${c.summary.slice(0, 84)}`);
        const f = r.findings.find(x => x.id === `privacy-framework:${c.id}`);
        if (f) console.log(`                → ${f.remediation}`);
      }
      console.log('');
    }
    console.log('  A control that is "manual" or "engine-gap" is NOT evidence of compliance.');
    console.log('  This organizes scanner evidence; a licensed assessor owns the attestation.\n');
  }

  // --fail-on gap is opt-in. A compliance opinion becomes a build failure only
  // when someone asks for it; defaulting to non-zero would break every pipeline
  // that adds this command to see the report.
  if (args.flags['fail-on'] === 'gap' && r.summary.gap > 0) return 1;
  return 0;
}

async function cmdAttest(args) {
  const scanRoot = path.resolve(args.flags.root || '.');

  if (args.flags.provenance) {
    const {
      buildProvenanceEvidenceBundle, signProvenanceEvidenceBundle, ensureKeyPair,
    } = await import('../src/posture/provenance-evidence-bundle.js');

    let scan;
    try { scan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); }
    catch { console.error('No .agentic-security/last-scan.json — run a scan first.'); return 2; }

    const findings = scan.findings || [];
    const wanted = args.flags.provenance === true ? undefined : args.flags.provenance;
    // `--provenance` alone (boolean flag) attests every finding WITH
    // findingProvenance present; `--provenance <id>` scopes to one.
    const subset = (wanted ? findings.filter((f) => f.id === wanted || f.stableId === wanted) : findings)
      .filter((f) => f.findingProvenance);
    if (!subset.length) {
      console.error(wanted ? `No finding matching "${wanted}" with findingProvenance.` : 'No findings with findingProvenance to attest.');
      return 2;
    }

    const kp = ensureKeyPair();
    if (kp.created) console.error(`Generated a new signing key at ${kp.privateKey} (public: ${kp.publicKey}).`);

    const outDir = statePath(scanRoot, 'attestations');
    fs.mkdirSync(outDir, { recursive: true });
    // repoIdentity: best-effort, from the same `git remote` lookup other
    // provenance modules avoid (no such lookup exists yet) — keep it simple,
    // pass null when unavailable rather than inventing a git-remote reader
    // here. A future task can enrich this; the field degrades honestly.
    const meta = { engineVersion: scan.engineVersion || null, repoIdentity: null, head: scan.commit || null };

    let n = 0;
    for (const f of subset) {
      const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(f, meta), kp.privateKeyPem);
      const name = `provenance-${(f.stableId || f.id || `finding-${n}`)}.json`.replace(/[^\w.-]/g, '_');
      fs.writeFileSync(path.join(outDir, name), JSON.stringify(bundle, null, 2) + '\n');
      n++;
    }
    console.log(`Signed ${n} provenance evidence bundle(s) → ${path.relative(scanRoot, outDir)}/`);
    console.log(`Public key (share this with whoever verifies): ${kp.publicKey}`);
    console.log('');
    console.log('A bundle proves its contents are unmodified since signing. It does NOT');
    console.log('prove the origin commit is correctly identified — read confidence.level.');
    return 0;
  }

  const {
    ensureKeyPair, buildEvidenceBundle, signEvidenceBundle,
  } = await import('../src/posture/evidence-bundle.js');

  let scan;
  try { scan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); }
  catch { console.error('No .agentic-security/last-scan.json — run a scan first.'); return 2; }

  const findings = scan.findings || [];
  const wanted = args.flags.id;
  const subset = wanted ? findings.filter(f => f.id === wanted || f.stableId === wanted) : findings;
  if (!subset.length) {
    console.error(wanted ? `No finding matching "${wanted}".` : 'No findings to attest.');
    return 2;
  }

  const kp = ensureKeyPair();
  if (kp.created) console.error(`Generated a new signing key at ${kp.privateKey} (public: ${kp.publicKey}).`);

  const outDir = statePath(scanRoot, 'attestations');
  fs.mkdirSync(outDir, { recursive: true });
  const meta = {
    engineVersion: scan.engineVersion || null,
    rulesetVersion: scan.rulesetVersion || null,
    bundleSha: scan.bundleSha || null,
    commit: scan.commit || null,
  };

  let n = 0;
  for (const f of subset) {
    const bundle = signEvidenceBundle(buildEvidenceBundle(f, meta), kp.privateKeyPem);
    const name = `${(f.stableId || f.id || `finding-${n}`)}.json`.replace(/[^\w.-]/g, '_');
    fs.writeFileSync(path.join(outDir, name), JSON.stringify(bundle, null, 2) + '\n');
    n++;
  }
  console.log(`Signed ${n} evidence bundle(s) → ${path.relative(scanRoot, outDir)}/`);
  console.log(`Public key (share this with whoever verifies): ${kp.publicKey}`);
  console.log('');
  console.log('A bundle proves its contents are unmodified since signing. It does NOT');
  console.log('prove the finding is real — read evidence.proofTier for that.');
  return 0;
}

// R4/D2 correctness follow-up: attestation.js ships TWO independent
// verifiers — verifyEvidenceBundle (per-finding, Ed25519, self-contained —
// only needs a public key) and verifyRunAttestation (whole-run, per-install
// HMAC, NOT self-contained — needs the caller to also supply the finding
// set to re-derive against). This CLI command only ever called the first;
// the second had zero production callers anywhere in the repo (confirmed by
// grep — only test/attestation.test.js called it). Auto-detect which
// artifact was handed in and dispatch to the matching verifier instead of
// silently misinterpreting a run-attestation as a (structurally different)
// evidence bundle.
function _asRunAttestation(obj) {
  if (obj && typeof obj.digest === 'string' && obj.canonicalisation) return obj;
  if (obj && obj.attestation && typeof obj.attestation.digest === 'string') return obj.attestation;
  return null;
}

// Verifies a run attestation the ONLY way it can be verified: by re-deriving
// the digest from a fresh scan and comparing. Unlike an evidence bundle
// (self-contained, just needs a public key), a run attestation is a claim
// about a FINDING SET, not a standalone signed blob — "does scanning this
// codebase right now reproduce the exact digest an earlier run attested"
// is the actual, meaningful question this command answers.
async function cmdVerifyRunAttestation(attestation, args) {
  const projectPath = path.resolve(args.flags.against || '.');
  if (!fs.existsSync(projectPath)) {
    console.error(`--against path does not exist: ${projectPath}`);
    return 2;
  }
  console.log(`Re-scanning ${projectPath} to check it reproduces the attested digest...`);
  const { runScan } = await import('../src/runScan.js');
  const { normalizeFindings } = await import('../src/report/index.js');
  const { effectiveVersion } = await import('../src/posture/ruleset-version.js');
  const { verifyRunAttestation } = await import('../src/posture/attestation.js');
  const { scan } = await runScan(projectPath);
  const r = verifyRunAttestation(attestation, {
    findings: normalizeFindings(scan),
    engineVersion: PKG_VERSION,
    rulesetVersion: effectiveVersion(projectPath).version,
    bundleSha: _bundleSha(),
    root: projectPath,
  });
  if (!r.ok) {
    console.error(`✗ INVALID — ${r.reason}`);
    return 1;
  }
  console.log('✓ VALID — a fresh scan of this project reproduces the attested digest exactly.');
  console.log('');
  console.log(`  digest:          ${attestation.digest}`);
  console.log(`  findingCount:    ${attestation.findingCount}`);
  console.log(`  proves:          ${attestation.proves}`);
  console.log(`  does NOT prove:  ${attestation.doesNotProve}`);
  return 0;
}

async function cmdVerifyAttestation(args) {
  const { verifyEvidenceBundle, keyPaths } = await import('../src/posture/evidence-bundle.js');
  // `args._[0]` is the command name itself — the same convention cmdScan uses.
  const file = args.flags.bundle || args._[1];
  if (!file) { console.error('Usage: agentic-security verify-attestation <bundle.json|last-scan.json> [--public-key <path>] [--against <project-path>]'); return 2; }

  let bundle;
  try {
    const raw = fs.readFileSync(path.resolve(file), 'utf8');
    // FR-705: transparently decrypt if this is an encrypted artifact (e.g.
    // an encrypted compliance-evidence.json) — a no-op for any plaintext
    // file, including every artifact from before encryption was ever
    // configured.
    const { maybeDecryptForRead } = await import('../src/posture/encryption-provider.js');
    bundle = JSON.parse(maybeDecryptForRead(raw));
  } catch (e) { console.error(`Could not read bundle: ${e.message}`); return 2; }

  const runAttestation = _asRunAttestation(bundle);
  if (runAttestation) return cmdVerifyRunAttestation(runAttestation, args);

  const keyFile = args.flags['public-key'] || keyPaths().publicKey;
  let publicKeyPem = null;
  try { publicKeyPem = fs.readFileSync(path.resolve(keyFile), 'utf8'); }
  catch { console.error(`Could not read public key at ${keyFile}. Pass --public-key <path>.`); return 2; }

  // FR-505: a compliance evidence manifest (@type: ComplianceEvidence) is a
  // third distinct shape this same command can be handed — auto-detected
  // the same way run-attestation-vs-finding-bundle already is, rather than
  // adding a fourth CLI command for what is, from an operator's point of
  // view, the same question ("is this artifact exactly what was signed").
  if (bundle['@type'] === 'ComplianceEvidence') {
    const { verifyComplianceEvidence } = await import('../src/posture/compliance-evidence-signing.js');
    const cr = verifyComplianceEvidence(bundle, publicKeyPem);
    if (!cr.ok) { console.error(`✗ INVALID — ${cr.reason}`); return 1; }
    console.log('✓ VALID — the compliance evidence manifest is exactly what the signer produced.');
    console.log('');
    console.log(`  framework: ${bundle.framework}  version: ${bundle.version}`);
    console.log(`  generated: ${bundle.generatedAt}`);
    if (bundle.evidenceDigest) console.log(`  evidence digest: ${bundle.evidenceDigest}`);
    console.log(`  compliant: ${bundle.summary?.compliant ?? 'n/a'}  non-compliant: ${bundle.summary?.nonCompliant ?? 'n/a'}  stale: ${bundle.summary?.stale ?? 0}  gap: ${bundle.summary?.gap ?? 0}`);
    return 0;
  }

  // Finding Provenance PRD M4 §4.1: a provenance evidence bundle
  // (schema: agentic-security/provenance-evidence@1) is a fourth distinct
  // shape this same command can be handed — same auto-detection chain as
  // the ComplianceEvidence branch above, dispatched by schema marker
  // rather than a new CLI verb. Must be checked BEFORE the fallback
  // verifyEvidenceBundle() call below, which assumes evidence-bundle.js's
  // own shape (`.evidence`, `.finding` with severity/vuln/file/line) and
  // would misinterpret a provenance bundle.
  const { verifyProvenanceEvidenceBundle, PROVENANCE_BUNDLE_SCHEMA } = await import('../src/posture/provenance-evidence-bundle.js');
  if (bundle.schema === PROVENANCE_BUNDLE_SCHEMA) {
    const pr = verifyProvenanceEvidenceBundle(bundle, publicKeyPem);
    if (!pr.ok) { console.error(`✗ INVALID — ${pr.reason}`); return 1; }
    const p = bundle.provenance || {};
    console.log('✓ VALID — the provenance record is exactly what the signer attested.');
    console.log('');
    console.log(`  finding: ${bundle.finding?.stableId || bundle.finding?.id || '?'}`);
    console.log(`  status: ${p.status || 'n/a'}   method: ${p.method || 'n/a'}`);
    // FR-PROV-026: findingOrigin.authorName is untrusted git commit metadata
    // (this bundle's signature only proves the BUNDLE wasn't tampered with —
    // it says nothing about what the original commit author put in their
    // name — see the "Signed, portable evidence" section of the root
    // CLAUDE.md), printed straight to the terminal by `verify-attestation`.
    if (p.findingOrigin) console.log(`  origin: ${p.findingOrigin.commit || '?'} by ${sanitizeForTerminal(p.findingOrigin.authorName) || '?'} on ${p.findingOrigin.authorDate || '?'}`);
    console.log(`  confidence: ${p.confidence?.level || 'n/a'} (${p.confidence?.score ?? 'n/a'})`);
    if ((p.limitations || []).length) console.log(`  limitations: ${p.limitations.join('; ')}`);
    console.log('');
    console.log(`  proves:        ${bundle.proves}`);
    console.log(`  does NOT prove: ${bundle.doesNotProve}`);
    return 0;
  }

  const r = verifyEvidenceBundle(bundle, publicKeyPem);
  if (!r.ok) {
    console.error(`✗ INVALID — ${r.reason}`);
    return 1;
  }
  const f = bundle.finding || {};
  console.log('✓ VALID — the bundle is exactly what the signer attested.');
  console.log('');
  console.log(`  ${f.severity ? `[${f.severity}] ` : ''}${f.vuln || '(no title)'}  ${f.file || '?'}:${f.line ?? '?'}`);
  console.log(`  cwe ${f.cwe || 'n/a'}   parser ${f.parser || 'n/a'}   proof tier ${bundle.evidence?.proofTier || 'n/a'}`);
  console.log('');
  console.log(`  proves:        ${bundle.proves}`);
  console.log(`  does NOT prove: ${bundle.doesNotProve}`);
  return 0;
}

// FR-1001 (assurance-hardening PRD): "effective policy is explainable."
// Loads whichever organization/repository/environment policy bundles exist
// under .agentic-security/policy-bundles/, verifies each against an
// operator-supplied public key, merges the valid ones (most-specific-wins),
// and prints BOTH the effective policy with per-key provenance AND every
// rejected bundle's scope and reason — a rejection is reported, never
// silently absent, so "tampered or expired policy is rejected" is visible
// through this same real command, not just a library-level guarantee.
async function cmdPolicyExplain(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const { loadPolicyBundles, loadPolicyPublicKey, resolveEffectivePolicy } = await import('../src/posture/policy-bundle.js');
  const entries = loadPolicyBundles(scanRoot);
  if (!entries.length) {
    console.log('No policy bundles found under .agentic-security/policy-bundles/ (organization.json, repository.json, environment.json).');
    return 0;
  }
  let publicKeyPem = null;
  const keyFile = args.flags['public-key'];
  if (keyFile) {
    try { publicKeyPem = fs.readFileSync(path.resolve(keyFile), 'utf8'); }
    catch (e) { console.error(`Could not read public key at ${keyFile}: ${e.message}`); return 2; }
  } else {
    publicKeyPem = loadPolicyPublicKey(scanRoot);
  }
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(entries, publicKeyPem);

  console.log(`Accepted (${accepted.length}): ${accepted.join(', ') || 'none'}`);
  if (rejected.length) {
    console.log(`Rejected (${rejected.length}):`);
    for (const r of rejected) console.log(`  ✗ ${r.scope}: ${r.reason}`);
  }
  console.log('');
  console.log('Effective policy:');
  const keys = Object.keys(effective).sort();
  if (!keys.length) {
    console.log('  (empty — no accepted bundle contributed any key)');
  } else {
    for (const k of keys) console.log(`  ${k} = ${JSON.stringify(effective[k])}  [from: ${provenance[k]}]`);
  }
  return 0;
}

// FR-1001: the operator-facing signing side, mirroring cmdAttest's own
// generate-key-if-absent pattern. Genuinely optional — an org can sign
// bundles with any Ed25519 tooling that produces the same canonical bytes
// (canonicalPolicyBytes is exported for exactly that interop reason) — but
// without SOME real caller for ensurePolicyKeyPair, this codebase's own
// dead-module guard is right to flag it: a key-generation function nobody
// calls is exactly the kind of code this project's premortems exist to
// catch, per posture/CLAUDE.md's dead-module convention.
async function cmdPolicySign(args) {
  const scanRoot = path.resolve(args.flags.root || '.');
  const { ensurePolicyKeyPair, buildPolicyBundle, signPolicyBundle } = await import('../src/posture/policy-bundle.js');
  const scope = args.flags.scope;
  if (!['organization', 'repository', 'environment'].includes(scope)) {
    console.error('Usage: agentic-security policy-sign --scope <organization|repository|environment> --policy <json-file> [--expires <ISO-date>] [--out <path>]');
    return 2;
  }
  const policyFile = args.flags.policy;
  if (!policyFile) { console.error('--policy <json-file> is required (the policy object to sign).'); return 2; }
  let policy;
  try { policy = JSON.parse(fs.readFileSync(path.resolve(policyFile), 'utf8')); }
  catch (e) { console.error(`Could not read --policy file: ${e.message}`); return 2; }

  const kp = ensurePolicyKeyPair();
  if (kp.created) console.error(`Generated a new policy-signing key at ${kp.privateKey} (public: ${kp.publicKey}). Distribute the PUBLIC key to every repository that must trust bundles you sign.`);

  const bundle = buildPolicyBundle(scope, policy, { expiresAt: args.flags.expires || null });
  if (!bundle) { console.error('Could not build a bundle — check --scope and that --policy is a JSON object.'); return 2; }
  const signed = signPolicyBundle(bundle, kp.privateKeyPem);

  const outFile = args.flags.out || `${scope}.json`;
  fs.writeFileSync(path.resolve(outFile), JSON.stringify(signed, null, 2) + '\n');
  console.log(`✓ signed ${scope} policy bundle written to ${outFile}`);
  console.log(`  public key for verification: ${kp.publicKey}`);
  return 0;
}

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
  const lastScanPath = statePath(target, 'findings.json');
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
  const lastScanPath = statePath(scanRoot, 'last-scan.json');
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
    writeStdout(JSON.stringify(f, null, 2) + '\n');
    if (f.fix?.code) { console.log('\n--- suggested patch ---\n'); console.log(f.fix.code); }
    console.log('\nUse --preview to see a diff, or --apply to apply directly.');
    return 0;
  }

  // FR-303 (assurance-hardening PRD): confine BEFORE the first read, not just
  // before the write — a traversal or symlink-planted f.file was previously
  // followed unquestioned for both the preview diff and the apply write (no
  // check existed on this path at all, unlike MCP's apply_fix). Applies to
  // preview too since both modes read from the same (until now, unconfined)
  // location.
  let absFile;
  try { absFile = confinePath(scanRoot, f.file, 'finding.file'); }
  catch (e) { console.error(`path-escape refused: ${e.message}`); return 4; }
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

  // --apply. FR-301/FR-302/FR-304 (assurance-hardening PRD): this used to
  // WARN on failed integrity and apply anyway, and skip verification
  // entirely (no rescan, no lint) — the same write-time safety gate MCP's
  // apply_fix already enforces for its caller-patch branch is now required
  // here too, through the one shared service.
  if (sigVerified !== true) {
    console.error(`Refusing to apply: last-scan.json integrity check ${sigVerified === false ? 'failed (tampered)' : 'could not verify (unsigned)'} — re-run \`agentic-security scan\` to refresh.`);
    return 4;
  }
  // FR-307/D-0024: before this, the CLI had no way to supply approval
  // evidence at all — a high-impact change (auth/authZ/crypto/PII/schema/
  // infra-privilege/public-API) was unconditionally refused via --apply
  // with no path to ever approve it, since fixMeta was never built here.
  // --approved-by/--approval-reason are optional and no-op for a candidate
  // that isn't high-impact — only apply-fix-service.js's own gate decides
  // whether they were needed.
  const approvedBy = args.flags['approved-by'] || null;
  const approvalReason = args.flags['approval-reason'] || null;
  // FR-1003: --author is optional and only has an effect when an operator
  // has opted into separation-of-duties in authorized-approvers.json — see
  // approver-registry.js's checkSeparationOfDuties.
  const patchAuthor = args.flags['author'] || null;
  const fixMeta = (approvedBy || approvalReason || patchAuthor)
    ? { approval: { approvedBy: approvedBy || '', reason: approvalReason || '' }, ...(patchAuthor ? { author: patchAuthor } : {}) }
    : null;
  const result = await applyVerifiedFix({
    scanRoot,
    finding: { file: f.file, id: f.id, stableId: f.stableId || null, ruleId: f.cwe || f.title, vuln: f.vuln || f.title },
    files: { [f.file]: newContent },
    fixMeta,
  });
  if (!result.ok) {
    console.error(`Refusing to apply: ${result.reason}`);
    if (result.budgetExceeded) console.error(`  (${result.attempts}/${result.maxAttempts} attempts already made for this finding)`);
    return 4;
  }
  const entry = result.written[0];
  console.log(`✓ applied fix ${entry.historyId}  (file: ${entry.file})`);
  console.log(`  backup: ${entry.backupPath}`);
  // FR-305: this used to unconditionally print "lint" as part of the
  // verified line, even when the linter was skipped (not installed) or no
  // test runner existed — claiming a required leg ran when it did not is
  // exactly the mislabeling FR-305 exists to prevent. Say plainly when the
  // pass was degraded and name what was skipped.
  if (result.verifiedFull) {
    console.log('  verified: yes — fully verified (rescan clean, no new medium+ finding, lint, tests)');
  } else {
    const degraded = (result.verify?.degradedLegs || []).join('; ') || 'a required leg';
    console.log(`  verified: yes, but NOT fully verified — rescan clean, no new medium+ finding; ${degraded}`);
  }
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

Read \`.agentic-security/last-scan.json\`. For every finding at or above \`\${1:-critical}\` severity, dispatch the security-fixer subagent — independent findings in parallel, serializing only findings that share a file. Each fix is inline-verified by apply_fix before it lands (finding gone + no new ≥medium + lint). Do NOT halt on the first failure: record each finding's outcome and continue, then report the full list and the auto-fix acceptance rate. Re-run \`/security-scan-all\` to confirm.
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

// `agentic-security explore [path] [--port <n>] [--keep-open]` — Milestone 3,
// sub-project Server, increment 1. Starts a local, read-only, loopback-only
// HTTP server over an already-built, signed lineage graph
// (.agentic-security/lineage-graph.json + .sig, written by a prior scan
// with AGENTIC_SECURITY_LINEAGE_DEEP=1). Never triggers a scan itself
// (Decision 2 of the scoping doc) — genuinely read-only end to end.
//
// Argument parsing mirrors cmdScan's own shape: scan root from args._[1]
// (defaulting to cwd), flags parsed via args.flags. On a failed
// loadSignedGraph, prints ONE of four distinct, clear error messages (see
// graph-loader.js) and returns a non-zero exit code WITHOUT ever starting
// the server. On success, starts the server and prints the URL + session
// token to stdout — the ONLY place the token is ever displayed; it is
// never written to a file and never logged again after this one print.
//
// The returned promise resolves (with exit code 0) only once the server
// itself closes (idle-timeout auto-stop, or an external kill) — matching
// every other cmdX(args) function's "resolves to an exit code" contract
// while keeping the process alive for as long as the server is listening.
async function cmdExplore(args) {
  const target = args._[1] || '.';
  const targetAbs = path.resolve(target);

  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const loaded = loadSignedGraph(targetAbs);
  if (!loaded.ok) {
    process.stderr.write(`agentic-security explore: ${loaded.message}\n`);
    return 1;
  }

  let port = 0;
  if (args.flags.port !== undefined) {
    if (typeof args.flags.port !== 'string' || !/^\d+$/.test(args.flags.port)) {
      process.stderr.write(`agentic-security explore: invalid --port value "${args.flags.port}" — must be a non-negative integer.\n`);
      return 1;
    }
    port = Number(args.flags.port);
    if (port > 65535) {
      process.stderr.write(`agentic-security explore: invalid --port value "${args.flags.port}" — must be <= 65535.\n`);
      return 1;
    }
  }
  const keepOpen = !!args.flags['keep-open'];

  const { createExploreServer } = await import('../src/server/http-server.js');
  const { generateSessionToken } = await import('../src/server/security.js');
  const sessionToken = generateSessionToken();

  let started;
  try {
    started = await createExploreServer({ graph: loaded.graph, port, sessionToken, keepOpen });
  } catch (e) {
    process.stderr.write(`agentic-security explore: failed to start server: ${e && e.message ? e.message : e}\n`);
    return 1;
  }
  const { server, port: actualPort } = started;

  // THE ONLY place the session token is ever displayed — never written to
  // a file, never logged by the server itself after this one print. The
  // token travels as a URL FRAGMENT (`#token=...`), never a query string:
  // a fragment is never sent to the server in any HTTP request (so it can
  // never be captured in an access log), yet the page's own JS can read it
  // once via location.hash and attach it as a header on every subsequent
  // /api/v1/* fetch() call (frontend/src/lib/api-client.js).
  process.stdout.write(`agentic-security explore: serving ${targetAbs}\n`);
  process.stdout.write(`  URL: http://127.0.0.1:${actualPort}/#token=${sessionToken}\n`);
  process.stdout.write('  Open this URL in a browser — the page authenticates itself automatically.\n');
  if (keepOpen) {
    process.stdout.write('  --keep-open set: no idle-timeout auto-stop. Ctrl-C to stop.\n');
  } else {
    process.stdout.write('  Server auto-stops after a period of inactivity, or Ctrl-C to stop now.\n');
  }

  return new Promise((resolve) => {
    server.on('close', () => resolve(0));
  });
}

// `agentic-security dataflow export [path] --format <fmt> --output <file>
// [--view <name>] [--size standard|2x] [--width <n>] [--height <n>]
// [--no-redact] [--filter <path>]` — Milestone 4, sub-project 5 (CLI +
// slash commands). Wires the six already-shipped M4 export/report
// functions (scanner/scripts/export-image.mjs's exportPng/exportPdf/
// exportSvg, scanner/src/lineage/export-json.js's exportGraphJSON,
// scanner/src/lineage/export-csv.js's exportFlowsCSV, and
// scanner/scripts/generate-html-report.mjs's generateHtmlReport) into
// one consistent CLI surface.
//
// Argument shape mirrors cmdExplore's own: scan root from args._[2]
// (args._[0]='dataflow', args._[1]='export', so the path — if given —
// is the THIRD positional), defaulting to cwd. Uses the identical
// loadSignedGraph contract and error-message pass-through as cmdExplore
// (scoping doc's own binding decision: never proceed past a graph-load
// failure).
//
// Exit codes: 0 success. 1 graph-load failure (loadSignedGraph's own
// four reasons). 2 export-stage failure — bad/missing flags, an
// unsupported format+view combination (svg + non-architecture view,
// rejected BEFORE any Chrome invocation — Chrome's own dump-failure
// reason for this case is confusing, not a good user-facing error), or
// a caught throw/{ok:false} from the underlying export function.
const DATAFLOW_EXPORT_FORMATS = new Set(['png', 'pdf', 'svg', 'json', 'csv', 'html']);
const DATAFLOW_EXPORT_VIEWS = new Set(['architecture', 'privacy', 'trace', 'inventory']);
const DATAFLOW_EXPORT_SIZES = { standard: { width: 1680, height: 945 }, '2x': { width: 3360, height: 1890 } };

async function cmdDataflowExport(args) {
  const target = args._[2] || '.';
  const targetAbs = path.resolve(target);

  const format = args.flags.format;
  if (!format || !DATAFLOW_EXPORT_FORMATS.has(format)) {
    process.stderr.write(`agentic-security dataflow export: --format must be one of ${[...DATAFLOW_EXPORT_FORMATS].join('|')} (got ${JSON.stringify(format)}).\n`);
    return 2;
  }
  const outputPath = args.flags.output;
  if (!outputPath || typeof outputPath !== 'string') {
    process.stderr.write('agentic-security dataflow export: --output <file> is required.\n');
    return 2;
  }
  const view = args.flags.view || 'architecture';
  if (!DATAFLOW_EXPORT_VIEWS.has(view)) {
    process.stderr.write(`agentic-security dataflow export: --view must be one of ${[...DATAFLOW_EXPORT_VIEWS].join('|')} (got ${JSON.stringify(view)}).\n`);
    return 2;
  }
  if (format === 'svg' && view !== 'architecture') {
    process.stderr.write('agentic-security dataflow export: --format svg only supports --view architecture — only the Architecture View renders a real <svg> element.\n');
    return 2;
  }

  const sizeFlag = args.flags.size;
  const hasWidthHeight = args.flags.width !== undefined || args.flags.height !== undefined;
  if (sizeFlag !== undefined && hasWidthHeight) {
    process.stderr.write('agentic-security dataflow export: --size and --width/--height are mutually exclusive — pick one.\n');
    return 2;
  }
  let width, height;
  if (sizeFlag !== undefined) {
    if (!Object.prototype.hasOwnProperty.call(DATAFLOW_EXPORT_SIZES, sizeFlag)) {
      process.stderr.write(`agentic-security dataflow export: --size must be one of ${Object.keys(DATAFLOW_EXPORT_SIZES).join('|')} (got ${JSON.stringify(sizeFlag)}).\n`);
      return 2;
    }
    ({ width, height } = DATAFLOW_EXPORT_SIZES[sizeFlag]);
  } else if (hasWidthHeight) {
    width = Number(args.flags.width);
    height = Number(args.flags.height);
    if (!Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(height) || height <= 0) {
      process.stderr.write('agentic-security dataflow export: --width/--height must both be positive integers.\n');
      return 2;
    }
  } else {
    ({ width, height } = DATAFLOW_EXPORT_SIZES.standard);
  }

  const redact = args.flags['no-redact'] ? false : true;
  if (!redact && format === 'csv') {
    process.stderr.write('agentic-security dataflow export: --no-redact has no effect on --format csv — CSV export does not support redaction yet.\n');
  }

  let filter;
  if (args.flags.filter) {
    const filterPath = path.resolve(args.flags.filter);
    try {
      filter = JSON.parse(fs.readFileSync(filterPath, 'utf8'));
    } catch (e) {
      process.stderr.write(`agentic-security dataflow export: could not read/parse --filter file "${args.flags.filter}": ${e.message}\n`);
      return 2;
    }
  }

  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const loaded = loadSignedGraph(targetAbs);
  if (!loaded.ok) {
    process.stderr.write(`agentic-security dataflow export: ${loaded.message}\n`);
    return 1;
  }
  const graph = loaded.graph;
  const opts = { view, width, height, redact, filter };

  let data;
  try {
    if (format === 'png' || format === 'pdf' || format === 'svg') {
      const { exportPng, exportPdf, exportSvg } = await import('../scripts/export-image.mjs');
      const fn = { png: exportPng, pdf: exportPdf, svg: exportSvg }[format];
      const result = await fn(graph, opts);
      if (!result.ok) {
        process.stderr.write(`agentic-security dataflow export: ${result.reason}\n`);
        return 2;
      }
      data = result.data;
    } else if (format === 'json') {
      const { exportGraphJSON } = await import('../src/lineage/export-json.js');
      data = JSON.stringify(exportGraphJSON(graph, opts), null, 2);
    } else if (format === 'csv') {
      const { exportFlowsCSV } = await import('../src/lineage/export-csv.js');
      data = exportFlowsCSV(graph);
    } else if (format === 'html') {
      const { generateHtmlReport } = await import('../scripts/generate-html-report.mjs');
      data = generateHtmlReport(graph, opts);
    }
  } catch (e) {
    process.stderr.write(`agentic-security dataflow export: export failed: ${e && e.message ? e.message : e}\n`);
    return 2;
  }

  const outAbs = path.resolve(outputPath);
  await fsp.mkdir(path.dirname(outAbs), { recursive: true });
  await fsp.writeFile(outAbs, data);
  process.stdout.write(`agentic-security dataflow export: wrote ${format} to ${outAbs}\n`);
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
      case 'export':   process.exit(await cmdExport(args));
      case 'legal-hold': process.exit(await cmdLegalHold(args));
      case 'calibration-feedback': process.exit(await cmdCalibrationFeedback(args));
      case 'calibration-report': process.exit(await cmdCalibrationReport(args));
      case 'hunt':     process.exit(await cmdHunt(args));
      case 'compliance': process.exit(await cmdCompliance(args));
      case 'attest':   process.exit(await cmdAttest(args));
      case 'verify-attestation': process.exit(await cmdVerifyAttestation(args));
      case 'policy-explain': process.exit(await cmdPolicyExplain(args));
      case 'policy-sign': process.exit(await cmdPolicySign(args));
      case 'rule-synth': process.exit(await cmdRuleSynth(args));
      case 'digest':   process.exit(await cmdDigest(args));
      case 'setup':    process.exit(await cmdSetup(args));
      case 'cache-report': {
        // Prompt-cache economics for the current session: parse the Claude Code
        // transcript usage and report cache-hit %, $ saved, and avoidable leaks.
        // Advisory/read-only — always exits 0.
        const { analyzeTranscript, formatCacheReport } = await import('../src/posture/cache-economics.js');
        const projectDir = path.resolve(args.flags.root || process.env.CLAUDE_PROJECT_DIR || process.cwd());
        const result = analyzeTranscript({ transcriptPath: args.flags.transcript, projectDir });
        if (args.flags.json) writeStdout(JSON.stringify(result, null, 2) + '\n');
        else console.log(formatCacheReport(result));
        process.exit(0);
      }
      case 'cache-statusline': {
        // F6 — one-line cost HUD for a Claude Code statusLine command. Also writes
        // .agentic-security/cache-telemetry.json for other pollers. Always exits 0.
        const { analyzeTranscript, renderCacheStatusLine } = await import('../src/posture/cache-economics.js');
        const projectDir = path.resolve(args.flags.root || process.env.CLAUDE_PROJECT_DIR || process.cwd());
        const result = analyzeTranscript({ transcriptPath: args.flags.transcript, projectDir });
        if (result.ok) {
          try {
            const dir = stateDir(projectDir);
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(path.join(dir, 'cache-telemetry.json'),
              JSON.stringify({ updatedAt: new Date().toISOString(), metrics: result.metrics, leaks: result.leaks }, null, 2));
          } catch { /* best-effort */ }
          console.log(renderCacheStatusLine(result.metrics));
        } else {
          console.log('agentic-security: no session cost yet');
        }
        process.exit(0);
      }
      case 'mcp':      {
        const { runStdio } = await import('../src/mcp/stdio.js');
        const root = args.flags.root || process.env.AGENTIC_SECURITY_MCP_ROOT || process.cwd();
        runStdio({ sessionRoot: path.resolve(root) });
        return;
      }
      case 'explore':  process.exit(await cmdExplore(args));
      case 'dataflow': {
        const sub = args._[1];
        if (sub === 'export') { process.exit(await cmdDataflowExport(args)); }
        process.stderr.write(`agentic-security dataflow: unknown subcommand "${sub}" — only "export" is supported.\n`);
        process.exit(2);
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
          writeStdout(JSON.stringify(r, null, 2) + '\n');
        } else if (!r.ok) {
          console.error(`cve-watch: ${r.reason || 'failed'}`);
        }
        process.exit(r.ok ? 0 : 1);
      }
      case 'pr-delta': {
        // Shadowscan: compute the security delta between two git refs.
        // Useful in PR CI to show ONLY what changed, not the absolute
        // finding count. Pairs with `pr-comment` to render the result.
        const { computePrDelta, renderPrDeltaText } = await import('../src/pr-delta.js');
        const root = args.flags.root || process.cwd();
        const baseRef = args.flags.base || args.flags.b;
        const headRef = args.flags.head || args.flags.h || 'HEAD';
        if (!baseRef) { console.error('pr-delta: --base <ref> is required'); process.exit(2); }
        const delta = await computePrDelta(path.resolve(root), { baseRef, headRef });
        if (args.flags.json) writeStdout(JSON.stringify(delta, null, 2) + '\n');
        else console.log(renderPrDeltaText(delta));
        // Exit non-zero if any critical/high introduced (useful as CI gate).
        const i = delta.summary?.introduced || {};
        const blocking = (i.critical || 0) + (i.high || 0);
        process.exit(args.flags['fail-on-introduced'] && blocking > 0 ? 1 : 0);
      }
      case 'pr-comment': {
        // Render the advisor-tone PR comment from a delta (stdin or
        // pr-delta --json output). Reads JSON from --in <path> or stdin.
        const { renderPrComment } = await import('../src/pr-comment.js');
        const { computePrDelta } = await import('../src/pr-delta.js');
        const fs2 = await import('node:fs');
        let delta;
        if (args.flags.base) {
          const root = args.flags.root || process.cwd();
          delta = await computePrDelta(path.resolve(root), {
            baseRef: args.flags.base, headRef: args.flags.head || 'HEAD',
          });
        } else if (args.flags.in) {
          delta = JSON.parse(fs2.readFileSync(args.flags.in, 'utf8'));
        } else {
          const data = await new Promise(r => {
            const chunks = []; process.stdin.on('data', c => chunks.push(c));
            process.stdin.on('end', () => r(Buffer.concat(chunks).toString('utf8')));
          });
          delta = JSON.parse(data);
        }
        const comment = renderPrComment(delta, {
          repoName: args.flags.repo, prNumber: args.flags.pr, prTitle: args.flags.title,
        });
        console.log(comment);
        process.exit(0);
      }
      case 'badge': {
        // Emit a live SVG badge from the most recent scan. Drop the URL
        // (or inline SVG) into README for pull-marketing.
        const { renderBadge } = await import('../src/badge.js');
        const root = args.flags.root || process.cwd();
        const format = args.flags.format || 'svg';
        const style = args.flags.style || 'flat';
        console.log(renderBadge({ format, style, scanRoot: path.resolve(root) }));
        process.exit(0);
      }
      case 'leaderboard-row': {
        // Generate one repo's leaderboard row (JSON). The future public
        // leaderboard at agentic-security.dev/leaderboard aggregates rows.
        const { leaderboardRowFor } = await import('../src/leaderboard.js');
        const root = args.flags.root || process.cwd();
        const repo = args.flags.repo;
        if (!repo) { console.error('leaderboard-row: --repo <owner/name> is required'); process.exit(2); }
        const row = leaderboardRowFor({ scanRoot: path.resolve(root), repo });
        writeStdout(JSON.stringify(row, null, 2) + '\n');
        process.exit(0);
      }
      case 'history': {
        // Time-travel scan. Walk N historical git refs within --since,
        // scan each, emit a per-ref timeline + introduced/resolved deltas
        // between consecutive snapshots.
        const { runHistory } = await import('../src/history-scan.js');
        const root = args.flags.root || process.cwd();
        const r = await runHistory(path.resolve(root), {
          since:    args.flags.since    || '6.months',
          interval: args.flags.interval || '1.month',
        });
        if (args.flags.json) writeStdout(JSON.stringify(r, null, 2) + '\n');
        else if (r.error) console.error(`history: ${r.error}`);
        else {
          console.log(`Scanned ${r.refs.length} refs.`);
          for (const ev of r.timeline) {
            console.log(`  ${ev.fromWhen} → ${ev.toWhen}: +${ev.introducedN} introduced, -${ev.resolvedN} resolved`);
          }
        }
        process.exit(r.error ? 1 : 0);
      }
      case 'what-if': {
        // Counterfactual scan. Apply file overlays + virtual deletes to
        // the working tree, scan, return delta vs. baseline.
        const { runWhatIf } = await import('../src/history-scan.js');
        const root = args.flags.root || process.cwd();
        const overlays = [];
        const overlayArg = args.flags.overlay;
        if (overlayArg) {
          // overlay format:  <relpath>:<source-file>
          for (const spec of Array.isArray(overlayArg) ? overlayArg : [overlayArg]) {
            const idx = spec.indexOf(':');
            if (idx < 0) continue;
            const file = spec.slice(0, idx);
            const src = spec.slice(idx + 1);
            try {
              overlays.push({ file, content: (await import('node:fs')).readFileSync(src, 'utf8') });
            } catch (e) {
              console.error(`what-if: cannot read overlay source ${src}: ${e.message}`);
              process.exit(1);
            }
          }
        }
        const remove = args.flags.remove
          ? (Array.isArray(args.flags.remove) ? args.flags.remove : [args.flags.remove])
          : [];
        const r = await runWhatIf(path.resolve(root), { overlays, remove });
        if (args.flags.json) writeStdout(JSON.stringify(r, null, 2) + '\n');
        else {
          console.log(`baseline: ${r.baselineFindings} findings`);
          console.log(`what-if:  ${r.whatIfFindings} findings (delta ${r.delta >= 0 ? '+' : ''}${r.delta})`);
          if (r.introduced.length) {
            console.log(`Introduced by this counterfactual:`);
            for (const f of r.introduced.slice(0, 20)) {
              console.log(`  + ${f.severity} ${f.vuln} (${f.file}:${f.line})`);
            }
          }
          if (r.removed.length) {
            console.log(`Removed by this counterfactual:`);
            for (const f of r.removed.slice(0, 20)) {
              console.log(`  - ${f.severity} ${f.vuln} (${f.file}:${f.line})`);
            }
          }
        }
        process.exit(0);
      }
      case 'version':  console.log(`agentic-security ${PKG_VERSION}  ·  created by ClearCapabilities.Com`); process.exit(0);
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

// Guard against running as the CLI entry point vs. being `import`ed (e.g. by
// scanner/test/cli/provenance-flags.test.js, which imports parseProvenanceFlags
// for a unit test). Without this, any import of this module — for a single
// named export — re-runs the entire CLI dispatch and calls process.exit(),
// killing whatever process did the importing.
//
// `import.meta.url === file://${process.argv[1]}` looks equivalent but is
// NOT: when this script is invoked through a symlink (exactly what
// `npm install -g`, `npx`, and `node_modules/.bin/<name>` all do for a
// package's `bin` entries — which is the documented `npx
// @clear-capabilities/agentic-security-scanner` install path), Node
// resolves `import.meta.url` to the symlink's realpath while
// `process.argv[1]` stays the symlink path as invoked, so the two never
// match, the guard is always false, and the CLI silently exits with no
// output. `import.meta.main` is resolved correctly through a symlink —
// verified live through an actual symlink, not just read about — see the
// Task 17 fix report. It was added in Node v24.2.0 (backported to
// v22.18.0) and is currently Stability 1.0 (early development) per Node's
// own docs — NOT stable, and NOT available on v20.11 as an earlier
// version of this comment incorrectly claimed. Concretely: it is
// `undefined` on Node 24.0.0/24.1.x, which satisfy this repo's declared
// `engines.node: ">=24.0.0"` floor, so `import.meta.main` alone would
// reproduce this exact bug (main() silently never runs) on a plain
// non-symlinked invocation under those two point releases. The `??`
// fallback below covers that gap without bumping the engines floor.
if (import.meta.main ?? (import.meta.url === `file://${process.argv[1]}`)) {
  main();
}
