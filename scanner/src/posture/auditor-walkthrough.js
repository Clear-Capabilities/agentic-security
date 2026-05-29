// Auditor-walkthrough generator.
//
// Produces a step-by-step narrative an engineering team can follow to
// demonstrate evidence for a compliance framework's controls to an
// external auditor.
//
// Built-in frameworks (all public-domain — no copyrighted text reproduced):
//
//   nist-csf-2          NIST Cybersecurity Framework 2.0
//   nist-ai-600-1       NIST AI Risk Management Framework, GenAI profile
//   owasp-asvs-5        OWASP Application Security Verification Standard 5.0
//   owasp-llm-top-10    OWASP Top 10 for LLM Applications 2025
//   eu-ai-act           EU AI Act (Regulation 2024/1689)
//   gdpr                General Data Protection Regulation
//   hipaa-security-rule HIPAA Security Rule (45 CFR Part 164)
//   ccpa                California Consumer Privacy Act
//
// Proprietary frameworks (SOC2 Trust Services Criteria, ISO 27001/27002,
// PCI-DSS, HITRUST CSF) are intentionally NOT bundled because their
// control text is copyrighted by their respective publishers. For those,
// the BYO mechanism is:
//
//   .agentic-security/compliance/<framework>/controls.json
//
// User supplies their own control mapping in the same shape as the
// bundled ones. The auditor-walkthrough renders evidence against it.
//
// Disclaimer: this module organizes scanner evidence into a narrative.
// It does not certify compliance. A licensed assessor (CPA / auditor /
// DPO) is responsible for the final attestation.

import * as fs from 'node:fs';
import * as path from 'node:path';

const BUNDLED_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), 'compliance-frameworks');
const STATE = '.agentic-security';

function _readJson(fp) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

/**
 * List the available frameworks (bundled + project-byo).
 */
export function listFrameworks(scanRoot) {
  const out = [];
  try {
    for (const fn of fs.readdirSync(BUNDLED_DIR)) {
      if (!fn.endsWith('.json')) continue;
      const fw = _readJson(path.join(BUNDLED_DIR, fn));
      if (fw && fw.id) out.push({ id: fw.id, name: fw.name, source: 'bundled', license: fw.license });
    }
  } catch {}
  if (scanRoot) {
    const projDir = path.join(scanRoot, STATE, 'compliance');
    if (fs.existsSync(projDir)) {
      try {
        for (const sub of fs.readdirSync(projDir)) {
          const fp = path.join(projDir, sub, 'controls.json');
          if (fs.existsSync(fp)) {
            const fw = _readJson(fp);
            if (fw && fw.id) out.push({ id: fw.id, name: fw.name, source: 'project', license: fw.license || 'user-provided' });
          }
        }
      } catch {}
    }
  }
  return out;
}

/**
 * Load a framework definition by id. Project BYO overrides bundled.
 */
export function loadFramework(scanRoot, id) {
  if (scanRoot) {
    const projFp = path.join(scanRoot, STATE, 'compliance', id, 'controls.json');
    if (fs.existsSync(projFp)) return _readJson(projFp);
  }
  for (const fn of fs.readdirSync(BUNDLED_DIR)) {
    if (!fn.endsWith('.json')) continue;
    const fw = _readJson(path.join(BUNDLED_DIR, fn));
    if (fw && fw.id === id) return fw;
  }
  return null;
}

/**
 * For each control, evaluate evidence against the current scan.
 *
 * Returns an array of:
 *   { control, status, observations[] }
 *
 * Status:
 *   'present'   — all mapsTo families have zero open critical findings AND
 *                 module artifacts exist
 *   'partial'   — some signal present but with open issues
 *   'absent'    — no signal / open critical findings on every mapsTo family
 *   'manual'    — control has no mapsTo (requires manual attestation)
 */
export function evaluateFramework(scanRoot, fw, scan) {
  const findings = (scan && Array.isArray(scan.findings)) ? scan.findings : [];
  const components = (scan && Array.isArray(scan.components)) ? scan.components : [];
  const families = new Map();
  for (const f of findings) {
    const k = f.family || 'unknown';
    if (!families.has(k)) families.set(k, []);
    families.get(k).push(f);
  }

  const results = [];
  for (const c of fw.controls || []) {
    const obs = [];
    let status = 'manual';
    const maps = Array.isArray(c.mapsTo) ? c.mapsTo : [];

    if (maps.length === 0) {
      obs.push('No automated mapping — requires manual evidence collection.');
      results.push({ control: c, status, observations: obs });
      continue;
    }

    let allCleared = true;
    let anySignal = false;
    for (const m of maps) {
      if (m.startsWith('family:')) {
        const fam = m.slice('family:'.length).split(':')[0];
        const open = (families.get(fam) || []).filter(f => !f.intentSuppressed && !f.pastDecision && (f.severity === 'critical' || f.severity === 'high'));
        if (open.length) {
          allCleared = false;
          obs.push(`${open.length} open ${fam} finding(s) at high/critical.`);
        } else {
          obs.push(`✓ ${fam}: no open critical/high findings.`);
        }
        anySignal = true;
      } else if (m.startsWith('module:')) {
        const mod = m.slice('module:'.length);
        const ARTIFACT = {
          'sbom-diff':            'sbom-history/',
          'license-attributions': 'ATTRIBUTIONS.md',
          'threat-model-auto':    'threat-model.json',
          'compliance-policy':    'compliance-evidence.json',
          'mcp-audit':            'mcp-audit.log',
          'fix-history':          'fix-history/log.json',
          'privacy-taint':        'dpia.md',
          'aibom':                'aibom.json',
          'attack-taxonomy':      'last-scan.json',
          'why-fired':            'last-scan.json',
          'scan-history':         'scan-history/',
          'integrity':            'last-scan.json.sig',
          'watch-mode':           'watch-status.json',
          'cve-alert-daemon':     'cve-alerts/',
          'triage':               'triage.json',
          'triage-memory':        'triage-memory.jsonl',
          'verifier':             'verifier-runs/',
          'calibration':          'calibration-seed.json',
          'holdout-eval':         'holdout-eval.jsonl',
          'sigstore-verify':      'sigstore-attestations/',
          'pre-edit-bodyguard':   '.../hooks/pre-edit-bodyguard.js',
          'apply-fix':            'fix-history/log.json',
          'security-fixer':       '.../agents/security-fixer.md',
          'mcp-tools':            '.../scanner/src/mcp/tools.js',
        };
        const target = ARTIFACT[mod];
        if (target && fs.existsSync(path.join(scanRoot, STATE, target))) {
          obs.push(`✓ ${mod}: ${target} present.`);
          anySignal = true;
        } else {
          obs.push(`✗ ${mod}: expected ${target || '(unmapped)'} not present.`);
          allCleared = false;
        }
      } else if (m.startsWith('rule:')) {
        // Could check whether a custom rule fires zero — leave a hint for now.
        obs.push(`(rule mapping) ${m} — verify manually that the bodyguard rule is enabled.`);
        anySignal = true;
      }
    }

    if (!anySignal) status = 'manual';
    else if (allCleared) status = 'present';
    else status = 'partial';

    results.push({ control: c, status, observations: obs });
  }
  return results;
}

/**
 * Render the walkthrough Markdown narrative.
 */
export function renderWalkthrough(fw, evaluation, opts = {}) {
  const lines = [];
  lines.push(`# Auditor walkthrough — ${fw.name}`);
  lines.push('');
  lines.push(`> Publisher: ${fw.publisher}`);
  lines.push(`> License: ${fw.license}`);
  if (fw.url) lines.push(`> Source: ${fw.url}`);
  lines.push('');
  lines.push('> **This walkthrough organizes scanner evidence into a narrative for an external auditor.** It does NOT certify compliance. A licensed assessor is responsible for the final attestation.');
  lines.push('');

  const present  = evaluation.filter(e => e.status === 'present').length;
  const partial  = evaluation.filter(e => e.status === 'partial').length;
  const absent   = evaluation.filter(e => e.status === 'absent').length;
  const manual   = evaluation.filter(e => e.status === 'manual').length;
  const total    = evaluation.length;
  lines.push(`## Summary`);
  lines.push('');
  lines.push(`Controls evaluated: **${total}**`);
  lines.push(`- ✅ Evidence present: **${present}**`);
  lines.push(`- 🟡 Partial evidence: **${partial}**`);
  lines.push(`- ⛔ No evidence: **${absent}**`);
  lines.push(`- 📝 Manual attestation required: **${manual}**`);
  lines.push('');

  lines.push(`## Controls — step by step`);
  lines.push('');
  for (const ev of evaluation) {
    const c = ev.control;
    const glyph = { present: '✅', partial: '🟡', absent: '⛔', manual: '📝' }[ev.status] || '?';
    lines.push(`### ${glyph} ${c.id}${c.function ? ` (${c.function})` : ''} — ${c.summary}`);
    lines.push('');
    if (c.evidence && c.evidence.length) {
      lines.push('**Evidence the auditor expects:**');
      for (const e of c.evidence) lines.push(`- ${e}`);
      lines.push('');
    }
    if (ev.observations.length) {
      lines.push('**Current state:**');
      for (const o of ev.observations) lines.push(`- ${o}`);
      lines.push('');
    }
    if (ev.status === 'absent' || ev.status === 'partial') {
      lines.push(`**Remediation:** address the bullet(s) above, then re-run \`/auditor-walkthrough ${fw.id}\` to update this report.`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Persist the walkthrough at .agentic-security/auditor-walkthroughs/<id>.md
 */
export function persistWalkthrough(scanRoot, fw, body) {
  const dir = path.join(scanRoot, STATE, 'auditor-walkthroughs');
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const fp = path.join(dir, `${fw.id}.md`);
  try { fs.writeFileSync(fp, body); } catch {}
  return fp;
}

export const _internals = { _readJson };
