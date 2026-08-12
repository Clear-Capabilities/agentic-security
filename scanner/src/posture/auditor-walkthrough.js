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
//   nist-privacy-1-1    NIST Privacy Framework 1.1 (see posture/privacy-framework.js
//                       for the assessment + remediation layer over it)
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

import { statePath, stateWritesEnabled } from './state-dir.js';
const BUNDLED_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), 'compliance-frameworks');
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
    const projDir = statePath(scanRoot, 'compliance');
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
    const projFp = statePath(scanRoot, 'compliance', id, 'controls.json');
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
// Stage 6 correctness audit: several compliance frameworks map controls to
// `family:auth-missing` / `family:authz`, but no detector in this codebase
// ever emits those literal family strings — the real missing-auth/authz
// detectors use `broken-access-control` (generic), `fastapi-missing-auth`,
// `springboot-missing-authz`, `laravel-missing-auth`, `quarkus-missing-authz`
// (framework-specific). Without this alias, a control mapped to
// auth-missing/authz read "present" (vacuously — the family bucket was
// always empty) even with a critical, unauthenticated route open. Listed
// under both compliance-side names since `broken-access-control` covers
// both "nobody checked" (missing auth) and "checked wrong" (broken authz)
// and it is strictly safer to over-count a real finding against both than
// to keep silently excluding it from either.
const COMPLIANCE_FAMILY_ALIAS = {
  'auth-missing': ['broken-access-control', 'fastapi-missing-auth', 'springboot-missing-authz', 'laravel-missing-auth', 'quarkus-missing-authz'],
  'authz': ['broken-access-control', 'idor', 'springboot-missing-authz', 'quarkus-missing-authz'],
};

export function evaluateFramework(scanRoot, fw, scan) {
  // CMP-2: last-scan.json (what this is actually handed in production) carries
  // findings across four separate channels — SAST (`findings`), secrets,
  // business-logic, and SCA (`supplyChain`) — because report/index.js's
  // normalizeFindings keeps them apart too. Reading only `scan.findings` made
  // every secrets/logic/SCA finding invisible to every framework's family:
  // mappings, e.g. a critical hardcoded secret never counted against a
  // control mapped to family:hardcoded-secret. Each channel's family default
  // mirrors normalizeFindings' own fallback for that channel so the two stay
  // in agreement about what family an untagged finding belongs to.
  const findings = (scan && Array.isArray(scan.findings)) ? scan.findings : [];
  const secrets = ((scan && Array.isArray(scan.secrets)) ? scan.secrets : [])
    .map(s => ({ ...s, family: s.family || 'hardcoded-secret' }));
  const logicVulns = (scan && Array.isArray(scan.logicVulns)) ? scan.logicVulns : [];
  const supplyChain = ((scan && Array.isArray(scan.supplyChain)) ? scan.supplyChain : [])
    .map(sc => ({ ...sc, family: sc.family || 'vulnerable-dep' }));
  const components = (scan && Array.isArray(scan.components)) ? scan.components : [];
  const families = new Map();
  for (const f of [...findings, ...secrets, ...logicVulns, ...supplyChain]) {
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
    // Tracks whether ANY family:/module: mapping in this control actually
    // passed (distinct from allCleared, which asks whether EVERY one did).
    // Feeds the 'absent' vs 'partial' distinction below: a control where
    // nothing at all checks out is a materially different auditor story
    // ("no evidence") than one that's mostly clean with one open gap
    // ("evidence with a gap") — both used to render as the same 'partial'.
    let anyCleared = false;
    // CMP-2: a rule: mapping's own observation says "verify manually" — it
    // is deliberately not code-checked. It used to set anySignal=true and
    // leave allCleared untouched, so a control whose ONLY mapping was rule:
    // resolved to 'present' (fully evidenced), the same status as a control
    // with real, checked evidence. Any rule: mapping present caps the
    // control at 'partial' — never 'present' — regardless of what the
    // family:/module: mappings in the same control found.
    let hasUnverifiableMapping = false;
    for (const m of maps) {
      if (m.startsWith('family:')) {
        // `family:X` and the subfamily-qualified `family:X:Y` (used by
        // owasp-llm-top-10 for LLM02/LLM06/LLM07) both used to collapse to
        // just `X` here — the `:Y` qualifier was parsed and then silently
        // dropped, so any finding of family X counted against every control
        // mapped to X regardless of which subfamily the control actually
        // named (four LLM controls flagged off one credential-in-prompt
        // finding). Detectors that emit a subfamily always set it, so
        // filtering is safe; findings with no subfamily set still count
        // (recall-preserving default — same precedent as relevance.js).
        const [fam, subfam] = m.slice('family:'.length).split(':');
        const aliasFams = COMPLIANCE_FAMILY_ALIAS[fam] || [];
        const candidates = [fam, ...aliasFams].flatMap(k => families.get(k) || []);
        const scoped = subfam ? candidates.filter(f => !f.subfamily || f.subfamily === subfam) : candidates;
        const open = scoped.filter(f => !f.intentSuppressed && !f.pastDecision && (f.severity === 'critical' || f.severity === 'high'));
        if (open.length) {
          allCleared = false;
          obs.push(`${open.length} open ${fam} finding(s) at high/critical.`);
        } else {
          obs.push(`✓ ${fam}: no open critical/high findings.`);
          anyCleared = true;
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
        // A '.../' sentinel marks a source-relative artifact (project source,
        // e.g. a hook or agent file) — resolve it against the scan root itself.
        // Everything else is a runtime artifact under the STATE dir. Without
        // this, `statePath(scanRoot, '.../x')` never resolves and the
        // control falsely reads "not present" for every project.
        const resolved = !target ? null
          : target.startsWith('.../') ? path.join(scanRoot, target.slice(4))
          : statePath(scanRoot, target);
        const label = target ? target.replace(/^\.\.\.\//, '') : '(unmapped)';
        if (resolved && fs.existsSync(resolved)) {
          obs.push(`✓ ${mod}: ${label} present.`);
          anySignal = true;
          anyCleared = true;
        } else {
          obs.push(`✗ ${mod}: expected ${label} not present.`);
          allCleared = false;
        }
      } else if (m.startsWith('rule:')) {
        // Could check whether a custom rule fires zero — leave a hint for now.
        obs.push(`(rule mapping) ${m} — verify manually that the bodyguard rule is enabled.`);
        anySignal = true;
        hasUnverifiableMapping = true;
      }
    }

    // 'absent' was documented (see the docstring above) as a fourth,
    // distinct status — a control where NOTHING passed at all — but the
    // assignment below never produced it; every non-present, non-manual
    // control rendered as 'partial' regardless of whether it was "mostly
    // clean with one gap" or "completely unevidenced". Only introduced for
    // the fully-automated case (no rule: mapping) to avoid reclassifying
    // any control that already reads 'partial' because of an inherently
    // unverifiable rule: mapping — that precedent (rule: caps at 'partial',
    // never reaching 'present' OR 'absent') is unchanged.
    if (!anySignal) status = 'manual';
    else if (hasUnverifiableMapping) status = 'partial';
    else if (allCleared) status = 'present';
    else if (!anyCleared) status = 'absent';
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
      lines.push(`**Remediation:** address the bullet(s) above, then re-run \`/compliance --walkthrough ${fw.id}\` to update this report.`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Persist the walkthrough at .agentic-security/auditor-walkthroughs/<id>.md
 */
export function persistWalkthrough(scanRoot, fw, body) {
  const dir = statePath(scanRoot, 'auditor-walkthroughs');
  if (!stateWritesEnabled()) return null;
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const fp = path.join(dir, `${fw.id}.md`);
  try { fs.writeFileSync(fp, body); } catch {}
  return fp;
}

export const _internals = { _readJson };
