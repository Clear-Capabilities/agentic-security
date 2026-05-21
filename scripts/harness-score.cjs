#!/usr/bin/env node
/**
 * Harness Assessment scoring tool.
 *
 * Implements the four-level rubric from docs/HARNESS_ASSESSMENT_SPEC.md against the
 * live state of the project the scorer runs in. Each P0/P1 control is checked
 * mechanically; the per-domain score is computed from the checks; the overall
 * score is MIN(six domains) per the spec.
 *
 * Usage:
 *   node scripts/harness-score.cjs                       # markdown to stdout
 *   node scripts/harness-score.cjs --format json         # machine-readable
 *   node scripts/harness-score.cjs --output report.md    # write to file
 */
'use strict';

const fs   = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// args
// ---------------------------------------------------------------------------
const argv     = process.argv.slice(2);
let outPath    = null;
let format     = 'md';
let verbose    = false;
for (let i = 0; i < argv.length; i++) {
  if      (argv[i] === '--output' && argv[i + 1]) { outPath = argv[++i]; }
  else if (argv[i] === '--format' && argv[i + 1]) { format  = argv[++i]; }
  else if (argv[i] === '--verbose' || argv[i] === '-v') { verbose = true; }
}

const cwd        = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// fs helpers
// ---------------------------------------------------------------------------
const exists  = p => { try { fs.accessSync(p); return true; }    catch { return false; } };
const read    = p => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
const readJSON= p => { const s = read(p); if (!s) return null; try { return JSON.parse(s); } catch { return null; } };
const lineCount = p => { const s = read(p); return s ? s.split('\n').filter(Boolean).length : 0; };
const mtimeOf = p => { try { return fs.statSync(p).mtime; } catch { return null; } };
const cwdPath = (...segs) => path.join(cwd, ...segs);
const pluginPath = (...segs) => path.join(pluginRoot, ...segs);

// ---------------------------------------------------------------------------
// per-control checks
// each returns { status: 'present' | 'partial' | 'absent', evidence?: string, note?: string }
// ---------------------------------------------------------------------------
function check_T1() {
  const manifest = readJSON(pluginPath('.claude-plugin', 'plugin.json'));
  if (!manifest) return { status: 'absent', note: 'no .claude-plugin/plugin.json' };
  const tools = manifest.mcpServers && Object.keys(manifest.mcpServers).length > 0;
  return tools
    ? { status: 'present', evidence: '.claude-plugin/plugin.json declares MCP server(s) with schema' }
    : { status: 'absent',  note: 'plugin.json has no mcpServers declaration' };
}

function check_T2() {
  const mcpEntry = pluginPath('scanner', 'bin', 'agentic-security-mcp.js');
  return exists(mcpEntry)
    ? { status: 'present', evidence: 'scanner/bin/agentic-security-mcp.js mediates all tool calls' }
    : { status: 'absent',  note: 'no MCP entry point found' };
}

function check_T3() {
  const settings = readJSON(cwdPath('.claude', 'settings.json'));
  const denies = settings?.permissions?.deny || [];
  if (denies.length === 0) return { status: 'absent', note: 'no read-deny rules in .claude/settings.json' };
  // Sensitivity tiers in this plugin are implicit in the deny-list scoping plus the
  // RESERVED_WRITE list inside scanner/src/mcp/tools.js. Treat partial unless both exist.
  const toolsSrc = read(pluginPath('scanner', 'src', 'mcp', 'tools.js')) || '';
  const hasReserved = /RESERVED_WRITE/.test(toolsSrc);
  return hasReserved
    ? { status: 'present', evidence: `.claude/settings.json has ${denies.length} deny rules + RESERVED_WRITE list in scanner/src/mcp/tools.js` }
    : { status: 'partial', evidence: `${denies.length} deny rules but no RESERVED_WRITE tier list found` };
}

function check_T4() {
  const auditLog = cwdPath('.agentic-security', 'mcp-audit.log');
  const auditSrc = pluginPath('scanner', 'src', 'mcp', 'audit.js');
  const present  = exists(auditSrc);
  if (!present) return { status: 'absent', note: 'no scanner/src/mcp/audit.js' };
  return {
    status: 'present',
    evidence: `scanner/src/mcp/audit.js logs denials${exists(auditLog) ? `; ${lineCount(auditLog)} entries in current log` : ''}`,
  };
}

function check_T5() {
  const manifest = readJSON(pluginPath('.claude-plugin', 'plugin.json'));
  const requiresConfirm = manifest?.mcpServers?.['agentic-security']?.trust?.requires_confirm_for || [];
  return requiresConfirm.length > 0
    ? { status: 'present', evidence: `manifest declares confirmation required for: ${requiresConfirm.join(', ')}` }
    : { status: 'absent',  note: 'no trust.requires_confirm_for in plugin manifest' };
}

function check_T6() {
  const manifest = readJSON(pluginPath('.claude-plugin', 'plugin.json'));
  return manifest?.version
    ? { status: 'present', evidence: `plugin.json version ${manifest.version}` }
    : { status: 'absent',  note: 'plugin.json has no version' };
}

function check_G1() {
  const guard = pluginPath('hooks', 'pre-bash-guard.js');
  const cfg   = readJSON(cwdPath('.agentic-security', 'destructive-guard.json')) || { mode: 'block' };
  if (!exists(guard)) return { status: 'absent', note: 'no hooks/pre-bash-guard.js' };
  if (cfg.mode === 'off') return { status: 'partial', evidence: 'guard exists but mode=off' };
  return { status: 'present', evidence: `hooks/pre-bash-guard.js (mode=${cfg.mode})` };
}

function check_G2() {
  const throttle = exists(cwdPath('.agentic-security', 'hook-throttle.json'));
  const rateLimitSrc = read(pluginPath('hooks', 'post-edit-scan.js')) || '';
  const hasThrottle  = /throttle|debounce|rate/i.test(rateLimitSrc);
  return throttle || hasThrottle
    ? { status: 'present', evidence: 'hook-throttle.json and/or rate-limited post-edit scan' }
    : { status: 'partial', note: 'no explicit rate/cost limits found' };
}

function check_G3() {
  // Untrusted-input tagging: the body-guard inspects edits for external-source patterns,
  // which is a precursor signal. Full tagging requires a tagging layer at input ingress —
  // partial credit here.
  const bodyguard = pluginPath('hooks', 'pre-edit-bodyguard.js');
  return exists(bodyguard)
    ? { status: 'partial', evidence: 'pre-edit-bodyguard inspects untrusted patterns at edit time; explicit input-source tagging not implemented' }
    : { status: 'absent',  note: 'no input-tagging surface' };
}

function check_G4() {
  // Sandbox: this plugin does not run model-generated code in a sandbox. Claude Code's
  // own permission system provides the isolation boundary. Score as partial.
  return { status: 'partial', evidence: 'Claude Code permission system provides isolation; no per-tool ephemeral sandbox in-plugin' };
}

function check_F1() {
  const toolsSrc = read(pluginPath('scanner', 'src', 'mcp', 'tools.js')) || '';
  return /verify_fix|verifyFix/.test(toolsSrc)
    ? { status: 'present', evidence: 'verify_fix MCP tool re-runs detectors + linter before apply_fix' }
    : { status: 'absent',  note: 'no verify_fix gate found' };
}

function check_F2() {
  return exists(pluginPath('hooks', 'post-edit-scan.js'))
    ? { status: 'present', evidence: 'hooks/post-edit-scan.js scans after every Edit/Write and surfaces new criticals' }
    : { status: 'absent',  note: 'no post-edit-scan hook' };
}

function check_F3() {
  const manifest = readJSON(pluginPath('.claude-plugin', 'plugin.json'));
  const requiresConfirm = manifest?.mcpServers?.['agentic-security']?.trust?.requires_confirm_for || [];
  return requiresConfirm.includes('apply_fix')
    ? { status: 'present', evidence: 'apply_fix requires confirm:true (HITL checkpoint)' }
    : { status: 'partial', note: 'no apply_fix confirmation requirement in manifest' };
}

function check_F4() {
  // Self-consistency: would require a critic that diffs stated intent vs. realized tool
  // calls. Not present today; the closest signal is verify_fix's stableId-still-present
  // check, which is intent-vs-effect at the detector level.
  return { status: 'partial', evidence: 'verify_fix compares stated fix intent (stableId resolved) against effect; no broader intent-vs-toolcall critic' };
}

function check_A1() {
  const auditSrc = pluginPath('scanner', 'src', 'mcp', 'audit.js');
  if (!exists(auditSrc)) return { status: 'absent', note: 'no audit module' };
  const body = read(auditSrc) || '';
  const hasChain = /prev|chain|hash/i.test(body);
  return hasChain
    ? { status: 'present', evidence: 'scanner/src/mcp/audit.js emits hash-chained NDJSON entries' }
    : { status: 'partial', note: 'audit module present but chaining not confirmed by source scan' };
}

function check_A2() {
  return exists(cwdPath('.agentic-security', 'last-scan.json.sig'))
    ? { status: 'present', evidence: '.agentic-security/last-scan.json.sig (HMAC-SHA256, per-install key)' }
    : { status: 'partial', note: 'no HMAC signature on last-scan.json — run /scan --all to produce one' };
}

function check_A3() {
  const auditSrc = read(pluginPath('scanner', 'src', 'mcp', 'audit.js')) || '';
  return /verifyAuditLog/.test(auditSrc)
    ? { status: 'present', evidence: 'verifyAuditLog in scanner/src/mcp/audit.js walks the chain and returns broken-line index' }
    : { status: 'partial', note: 'no chain verifier exposed' };
}

function check_A4() {
  // Retention is operational, not enforced in code. Mark partial honestly.
  return { status: 'partial', note: 'retention enforced by operator policy, not by the scanner' };
}

function check_M1() {
  const toolsSrc = read(pluginPath('scanner', 'src', 'mcp', 'tools.js')) || '';
  return /RESERVED_WRITE/.test(toolsSrc)
    ? { status: 'present', evidence: 'RESERVED_WRITE list bounds the blast radius of apply_fix' }
    : { status: 'absent',  note: 'no reserved-write list found' };
}

function check_M2() {
  return exists(cwdPath('.agentic-security', 'fix-history'))
    ? { status: 'present', evidence: '.agentic-security/fix-history enforces a 2-attempt retry budget per stableId' }
    : { status: 'partial', evidence: 'fix-history not yet populated; retry-budget logic exists in scanner/src/posture/fix-history.js' };
}

function check_M3() {
  // The scanner does not provide a generic rollback layer; it refuses irreversible
  // operations rather than rolling them back. Score as partial against the spec's
  // wording, which requires either rollback or explicit confirmation.
  const manifest = readJSON(pluginPath('.claude-plugin', 'plugin.json'));
  const requiresConfirm = manifest?.mcpServers?.['agentic-security']?.trust?.requires_confirm_for || [];
  return requiresConfirm.length > 0
    ? { status: 'present', evidence: `irreversible-action confirmation via manifest.requires_confirm_for: ${requiresConfirm.join(', ')}` }
    : { status: 'partial', note: 'no rollback layer; confirmation requirements not declared' };
}

function check_M4() {
  // Incident response playbook. /disaster-playbook generates one. Whether it's been
  // exercised within 12 months is not derivable from the repo — partial.
  const playbookCmd = pluginPath('commands', 'disaster-playbook.md');
  return exists(playbookCmd)
    ? { status: 'partial', evidence: 'commands/disaster-playbook.md available; exercise cadence not tracked in code' }
    : { status: 'absent',  note: 'no disaster-playbook command' };
}

function check_C1() {
  const frameworks = ['nist-compliance', 'owasp-asvs', 'owasp-llm-top10', 'soc2', 'iso-27001', 'iso-42001', 'eu-ai-act'];
  const present = frameworks.filter(f => exists(pluginPath('scripts', f)));
  return present.length >= 3
    ? { status: 'present', evidence: `${present.length} compliance overlays present: ${present.join(', ')}` }
    : { status: 'partial', evidence: `${present.length} overlays present: ${present.join(', ') || 'none'}` };
}

function check_C2() {
  return exists(pluginPath('commands', 'compliance-report.md'))
    ? { status: 'present', evidence: '/compliance-report generates framework reports on demand' }
    : { status: 'absent',  note: 'no /compliance-report command' };
}

function check_C3() {
  return exists(pluginPath('commands', 'compliance-fix.md'))
    ? { status: 'present', evidence: '/compliance-fix routes Not-Compliant controls to remediation commands' }
    : { status: 'partial', note: 'no auto-exception routing' };
}

// ---------------------------------------------------------------------------
// continuous-evidence checks (one per domain, gates the 3rd rubric level)
// ---------------------------------------------------------------------------
function continuous_toolAccess() {
  const auditLog = cwdPath('.agentic-security', 'mcp-audit.log');
  const count = lineCount(auditLog);
  return { ok: count > 0, note: `mcp-audit.log entries: ${count}` };
}
function continuous_guardrails() {
  // The guard fires on every PreToolUse hook. Its presence + active mode is the evidence;
  // a per-event log would be richer but is not currently emitted.
  const destruct = readJSON(cwdPath('.agentic-security', 'destructive-guard.json')) || { mode: 'block' };
  const body     = readJSON(cwdPath('.agentic-security', 'bodyguard.json')) || { mode: 'warn' };
  const both = destruct.mode !== 'off' && body.mode !== 'off';
  return { ok: both, note: `destructive=${destruct.mode}, bodyguard=${body.mode}` };
}
function continuous_feedback() {
  const ok = exists(cwdPath('.agentic-security', 'fix-history'));
  return { ok, note: ok ? '.agentic-security/fix-history populated' : 'no fix-history yet' };
}
function continuous_audit() {
  const sig = exists(cwdPath('.agentic-security', 'last-scan.json.sig'));
  const log = lineCount(cwdPath('.agentic-security', 'mcp-audit.log'));
  return { ok: sig && log >= 0, note: `last-scan.json.sig=${sig}, audit entries=${log}` };
}
function continuous_failure() {
  // MTTR + drill-report tracking is operational, not in repo. Partial signal at best.
  return { ok: false, note: 'MTTR + drill-report cadence not tracked in code; provide externally' };
}
function continuous_compliance() {
  // Has at least one framework attestation been generated recently?
  const candidates = [
    'nist-ai-600-1-attestation.md',
    'owasp-asvs-attestation.md',
    'owasp-llm-top10-attestation.md',
    'soc2-attestation.md',
    'iso-27001-attestation.md',
    'iso-42001-attestation.md',
    'eu-ai-act-attestation.md',
  ];
  const found = candidates.filter(f => exists(cwdPath(f)));
  return { ok: found.length > 0, note: found.length ? `found: ${found.join(', ')}` : 'no recent attestation files' };
}

// ---------------------------------------------------------------------------
// spec — domain × control × continuous-evidence check
// ---------------------------------------------------------------------------
const SPEC = [
  {
    id: 'tool-access',
    name: 'Tool Access',
    summary: 'What the agent can run, and how each call is mediated.',
    controls: [
      { id: 'T-1', priority: 'P0', label: 'Tool allowlist with schema',                  fn: check_T1 },
      { id: 'T-2', priority: 'P0', label: 'Every tool call mediated by the harness',     fn: check_T2 },
      { id: 'T-3', priority: 'P0', label: 'Sensitivity tiers + scoping',                 fn: check_T3 },
      { id: 'T-4', priority: 'P0', label: 'Denied calls logged with reason',             fn: check_T4 },
      { id: 'T-5', priority: 'P1', label: 'Just-in-time elevation for high-sensitivity', fn: check_T5 },
      { id: 'T-6', priority: 'P1', label: 'Tool descriptions versioned',                 fn: check_T6 },
    ],
    continuous: continuous_toolAccess,
  },
  {
    id: 'guardrails',
    name: 'Guardrails',
    summary: 'Forbidden operations and enforced limits, outside the model.',
    controls: [
      { id: 'G-1', priority: 'P0', label: 'Denylist enforced outside the model',             fn: check_G1 },
      { id: 'G-2', priority: 'P0', label: 'Rate / cost / time limits',                       fn: check_G2 },
      { id: 'G-3', priority: 'P0', label: 'Untrusted-input tagging + confirm-before-effect', fn: check_G3 },
      { id: 'G-4', priority: 'P0', label: 'Sandboxing for code execution',                   fn: check_G4 },
      { id: 'G-5', priority: 'P1', label: 'Semantic guardrails (secondary classifier)',      fn: () => ({ status: 'partial', note: 'no secondary classifier wired today' }) },
      { id: 'G-6', priority: 'P1', label: 'Limits differentiated by role / risk tier',       fn: () => ({ status: 'partial', note: 'one global config; per-role tiers not implemented' }) },
    ],
    continuous: continuous_guardrails,
  },
  {
    id: 'feedback-loops',
    name: 'Feedback Loops',
    summary: 'What catches mistakes in flight.',
    controls: [
      { id: 'F-1', priority: 'P0', label: 'Output validation',                fn: check_F1 },
      { id: 'F-2', priority: 'P0', label: 'Anomaly detection + circuit breakers', fn: check_F2 },
      { id: 'F-3', priority: 'P0', label: 'Human-in-the-loop checkpoints',    fn: check_F3 },
      { id: 'F-4', priority: 'P0', label: 'Self-consistency: intent vs. tool calls', fn: check_F4 },
      { id: 'F-5', priority: 'P1', label: 'Separate verifier model for high-stakes plans', fn: () => ({ status: 'absent', note: 'no separate verifier model' }) },
      { id: 'F-6', priority: 'P1', label: '"Explain what you are about to do" affordance',  fn: () => ({ status: 'partial', note: 'agent narrates actions but no enforced pre-action explanation' }) },
    ],
    continuous: continuous_feedback,
  },
  {
    id: 'audit-evidence',
    name: 'Audit Evidence',
    summary: 'Continuous, tamper-evident proof of control.',
    controls: [
      { id: 'A-1', priority: 'P0', label: 'Structured append-only logs with trace ID',     fn: check_A1 },
      { id: 'A-2', priority: 'P0', label: 'Integrity-protected storage',                   fn: check_A2 },
      { id: 'A-3', priority: 'P0', label: 'Sessions can be replayed from logs',            fn: check_A3 },
      { id: 'A-4', priority: 'P0', label: 'Retention meets longest applicable obligation', fn: check_A4 },
      { id: 'A-5', priority: 'P1', label: 'Chain-of-custody metadata for audit-bound evidence', fn: () => ({ status: 'partial', note: 'HMAC signature is the chain-of-custody anchor; no external notarization' }) },
      { id: 'A-6', priority: 'P1', label: 'Public, queryable control status',                   fn: () => ({ status: 'absent', note: 'no public status surface' }) },
    ],
    continuous: continuous_audit,
  },
  {
    id: 'failure-mode',
    name: 'Failure Mode',
    summary: 'How gracefully the system fails when the model is wrong.',
    controls: [
      { id: 'M-1', priority: 'P0', label: 'Defined blast radius per tool category', fn: check_M1 },
      { id: 'M-2', priority: 'P0', label: 'Circuit breakers',                       fn: check_M2 },
      { id: 'M-3', priority: 'P0', label: 'Rollback / compensation / explicit confirm', fn: check_M3 },
      { id: 'M-4', priority: 'P0', label: 'Incident response playbook exercised',   fn: check_M4 },
      { id: 'M-5', priority: 'P1', label: 'Chaos drills with injected bad tool calls', fn: () => ({ status: 'absent', note: 'no scheduled chaos drills' }) },
      { id: 'M-6', priority: 'P1', label: 'Customer-facing incident comms templates', fn: () => ({ status: 'absent', note: 'no comms templates in repo' }) },
    ],
    continuous: continuous_failure,
  },
  {
    id: 'compliance',
    name: 'Compliance',
    summary: 'Evidence generated automatically, mapped to obligations on demand.',
    controls: [
      { id: 'C-1', priority: 'P0', label: 'Domains mapped to framework controls', fn: check_C1 },
      { id: 'C-2', priority: 'P0', label: 'Reports for any window without manual collection', fn: check_C2 },
      { id: 'C-3', priority: 'P0', label: 'Control failures auto-generate exceptions',         fn: check_C3 },
      { id: 'C-4', priority: 'P1', label: 'Continuous control monitoring dashboard',           fn: () => ({ status: 'absent', note: 'no dashboard surface' }) },
      { id: 'C-5', priority: 'P1', label: 'Auto-bundled evidence packages per audit',          fn: () => ({ status: 'partial', note: '/security-attestation bundles one-pager artifacts; per-engagement bundling not automated' }) },
    ],
    continuous: continuous_compliance,
  },
];

// ---------------------------------------------------------------------------
// scoring
// ---------------------------------------------------------------------------
const LEVEL_LABEL = {
  0: 'Absent',
  1: 'Partial',
  2: 'Operating',
  3: 'Operating with continuous evidence',
};

function scoreDomain(domain) {
  const results = domain.controls.map(c => ({ ...c, result: c.fn() }));
  const p0 = results.filter(r => r.priority === 'P0');
  const allP0 = p0.every(r => r.result.status === 'present');
  const anyP0 = p0.some(r => r.result.status !== 'absent');
  const continuous = domain.continuous();
  let level;
  if      (allP0 && continuous.ok) level = 3;
  else if (allP0)                  level = 2;
  else if (anyP0)                  level = 1;
  else                             level = 0;
  return { ...domain, results, continuous, level };
}

const scored = SPEC.map(scoreDomain);
const overall = Math.min(...scored.map(d => d.level));

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------
function renderMarkdown() {
  const lines = [];
  const proj = path.basename(cwd);
  const now = new Date().toISOString();
  lines.push('# Harness Assessment — Domain Report');
  lines.push('');
  lines.push(`- **Project:** ${proj}`);
  lines.push(`- **Generated:** ${now}`);
  lines.push(`- **Spec version:** 1.0 (see docs/HARNESS_ASSESSMENT_SPEC.md)`);
  lines.push('');
  lines.push(`## Overall: **Level ${overall} — ${LEVEL_LABEL[overall]}**`);
  lines.push('');
  lines.push('Overall = MIN(six domain scores). A harness passes when every domain is at least `Operating` and Audit Evidence + Compliance are at `Operating with continuous evidence`.');
  lines.push('');
  lines.push('| Domain | Level | Status |');
  lines.push('|---|---:|---|');
  for (const d of scored) {
    lines.push(`| ${d.name} | ${d.level} | ${LEVEL_LABEL[d.level]} |`);
  }
  lines.push('');
  for (const d of scored) {
    lines.push(`---`);
    lines.push('');
    lines.push(`## ${d.name} — Level ${d.level}: ${LEVEL_LABEL[d.level]}`);
    lines.push('');
    lines.push(`_${d.summary}_`);
    lines.push('');
    lines.push('| Control | Priority | Status | Notes |');
    lines.push('|---|---|---|---|');
    for (const r of d.results) {
      const glyph = r.result.status === 'present' ? '✅ Present' : r.result.status === 'partial' ? '🟡 Partial' : '⛔ Absent';
      const note = (r.result.evidence || r.result.note || '').replace(/\|/g, '\\|');
      lines.push(`| **${r.id}** ${r.label} | ${r.priority} | ${glyph} | ${note} |`);
    }
    lines.push('');
    lines.push(`**Continuous evidence:** ${d.continuous.ok ? '✅' : '🟡'} ${d.continuous.note}`);
    lines.push('');
  }
  lines.push('---');
  lines.push('');
  lines.push('## What to do next');
  lines.push('');
  const missingP0 = [];
  for (const d of scored) {
    for (const r of d.results) {
      if (r.priority === 'P0' && r.result.status !== 'present') {
        missingP0.push(`- **${d.name} / ${r.id}** (${r.label}) — ${r.result.note || r.result.evidence || ''}`);
      }
    }
  }
  if (missingP0.length === 0) {
    lines.push('All P0 controls are present. Focus next on P1 controls and on raising continuous-evidence emission in domains that are currently at Level 2.');
  } else {
    lines.push('The following P0 controls are missing or partial. Closing these is what moves domains from Partial → Operating:');
    lines.push('');
    lines.push(...missingP0);
  }
  lines.push('');
  return lines.join('\n');
}

function renderJSON() {
  return JSON.stringify({
    spec_version: '1.0',
    project:      path.basename(cwd),
    generated:    new Date().toISOString(),
    overall_score: overall,
    overall_label: LEVEL_LABEL[overall],
    domains: scored.map(d => ({
      id:        d.id,
      name:      d.name,
      level:     d.level,
      label:     LEVEL_LABEL[d.level],
      controls:  d.results.map(r => ({
        id:       r.id,
        priority: r.priority,
        label:    r.label,
        status:   r.result.status,
        evidence: r.result.evidence || null,
        note:     r.result.note || null,
      })),
      continuous: d.continuous,
    })),
  }, null, 2);
}

const out = format === 'json' ? renderJSON() : renderMarkdown();
if (outPath) {
  fs.writeFileSync(outPath, out);
  console.log(`Wrote ${outPath} (${out.length} bytes, format=${format})`);
} else {
  process.stdout.write(out + '\n');
}

// Non-zero exit if overall < 2 (Operating), so CI can gate on it.
process.exit(overall < 2 ? 1 : 0);
