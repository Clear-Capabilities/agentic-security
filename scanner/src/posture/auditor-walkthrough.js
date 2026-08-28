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
// Disclaimer: this module organizes scanner evidence into a narrative. It
// does not certify compliance. See evidence-grade-wording.js for why the
// emitted disclaimer names all three assurance tiers explicitly (this
// module's own is one of the ones that used to get the terminology
// backwards — "a licensed assessor is responsible for the final
// attestation" describes independent certification, not attestation).

import * as fs from 'node:fs';
import * as path from 'node:path';

import { statePath, stateWritesEnabled } from './state-dir.js';
import { EVIDENCE_GRADE_DISCLAIMER_SHORT } from './evidence-grade-wording.js';
import { COMPLIANCE_FAMILY_ALIAS, resolveFamilyKeys } from './family-resolve.js';
import { strengthOfControl as _strengthOfControl } from './coverage-strength.js';

// Re-exported so existing callers/tests keep importing these from here.
export { COMPLIANCE_FAMILY_ALIAS, resolveFamilyKeys };

// FR-PROV-016 (M2): "earliest proven open condition" among a control's
// contributing findings. Prefers a finding whose findingProvenance resolved
// findingOrigin.status:'complete' (the OLDEST such authorDate wins); falls
// back to 'partial' entries with a resolved findingOrigin.authorDate when no
// complete one exists. Never fabricates an origin — zero usable entries is
// reported as null/'unknown', not the repo's first commit or "now".
export function deriveComplianceProvenance(findings) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const withOrigin = list
    .map((f) => ({ f, fp: f && f.findingProvenance }))
    .filter((x) => x.fp && x.fp.findingOrigin && x.fp.findingOrigin.authorDate);
  const complete = withOrigin.filter((x) => x.fp.status === 'complete');
  const partial = withOrigin.filter((x) => x.fp.status === 'partial');
  // authorDate is git's `%aI` (strict ISO-8601, author's LOCAL UTC offset —
  // see git-evidence.js's commitMeta), never normalized to Z. Two commits
  // authored in different timezones near a day boundary can lexically sort
  // in the wrong chronological order, so compare actual instants via
  // Date.parse, never the raw strings.
  const pickEarliest = (arr) => arr.reduce(
    (min, x) => (!min || Date.parse(x.fp.findingOrigin.authorDate) < Date.parse(min.fp.findingOrigin.authorDate)) ? x : min,
    null,
  );
  const best = complete.length ? pickEarliest(complete) : (partial.length ? pickEarliest(partial) : null);
  return {
    derivedFrom: [...new Set(list.map((f) => f && f.id).filter(Boolean))],
    // Only commit/authorDate/authorName are ever read from findingOrigin
    // here — this object is a SIBLING field to findingProvenance (not
    // nested inside it), so it bypasses the redactFindingProvenance sweep
    // that runs at report/mcp output boundaries. authorEmail must never be
    // added to this shape without first routing it through
    // redactFindingProvenance.
    earliestOrigin: best ? {
      commit: best.fp.findingOrigin.commit || null,
      authorDate: best.fp.findingOrigin.authorDate,
      authorName: best.fp.findingOrigin.authorName || null,
    } : null,
    confidence: complete.length ? 'high' : (partial.length ? 'low' : 'unknown'),
    limitations: best ? [] : ['no contributing finding resolved a verified origin'],
  };
}

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
// CMP-1 (Stage 6 follow-up): grown incrementally by cross-referencing every
// `family:` string the bundled compliance-frameworks/*.json files reference
// against what src/sast + src/posture actually emit (a small, closed
// problem — only the strings a control actually maps to, not a universal
// vocabulary registry). k8s-admission.js's real rule id is
// `k8s-pod-privileged`; `nist-csf-2.json`/`hipaa-security-rule.json` map to
// the compliance-side spelling `k8s-pod-security-privileged`, which no
// detector ever emitted.

// CMP-1 audit trail: every `family:` string referenced by the bundled
// compliance-frameworks/*.json files was cross-checked against real
// detector output; entries above are the confirmed naming mismatches with a
// real detector to alias, and `mcp-audit.js`/`sca/dep-confusion.js` were
// fixed at the SOURCE (they now set `family` explicitly) rather than
// aliased, since the finding constructors themselves were the root cause.
//
// CORRECTION (measured, not read): this comment used to claim four families
// had no producer at all — `crypto-tls-version`, `nosql-injection`,
// `pii-exposure` and `data-exposure` — and that every control mapped to one
// of them therefore read `manual`/`engine-gap` rather than a false `present`.
// BOTH halves were wrong. Nothing implemented the engine-gap treatment (see
// COMPLIANCE_FAMILY_GAPS below), and all four families DO have producers:
// a sweep of 331 real scan roots (bench/family-producers/OBSERVED.json)
// observed crypto-tls-version, nosql-injection and data-exposure twice each,
// and `pii-exposure` is emitted by dataflow/privacy-taint.js:129.
//
// The lesson is recorded because it cost a wrong commit: a family is not a
// gap because a grep or a source comment says so. Several detectors pass
// `family` POSITIONALLY (`_shape(file, line, ruleId, vuln, fam, …)` in
// cloud-iam.js, crypto-protocol.js, k8s-admission.js, ml-supply-chain.js),
// so no textual search enumerates the real vocabulary. Only running the
// engine does.

// ...which the prose above ASSERTED but nothing enforced. A `family:` mapping
// with no detector behind it produces an empty bucket, and an empty bucket was
// reported as `✓ no open critical/high findings` — identical to a genuine pass.
// So the four known-unevidenceable families read as fully evidenced controls,
// which is precisely the outcome the comment says is avoided.
//
// Declaring them here makes the claim load-bearing: the evaluator consults this
// map (see the `family:` branch below) and caps such a control at `partial`
// with an explicit disclosure, and `test/compliance-mapping-liveness.test.js`
// fails if an entry loses its reason, duplicates an alias, or stops being
// referenced by any framework.
//
// Membership is deliberately conservative — these four come from the CMP-1
// audit recorded above, each confirmed to be referenced only by CONSUMER
// tables (attack-taxonomy, risk-dollars, threat-model classifiers) with no
// producing detector. A family is NOT added here merely because a static grep
// or a fixture sweep failed to observe it: several detectors pass `family`
// positionally (`_shape(file, line, ruleId, vuln, fam, …)` in cloud-iam.js,
// crypto-protocol.js, k8s-admission.js, ml-supply-chain.js), so neither source
// enumerates the real vocabulary on its own. Wrongly declaring a live family a
// gap would suppress a control that does work.
export const COMPLIANCE_FAMILY_GAPS = {
  // Deliberately EMPTY. Every family currently mapped by a bundled framework
  // has a producer, verified against bench/family-producers/OBSERVED.json.
  //
  // The mechanism below is retained because the hazard is real and structural:
  // the evaluator resolves `family:X` against a Map keyed by finding.family, so
  // a mapping nothing produces yields an empty bucket, and an empty bucket used
  // to render as `✓ no open critical/high findings` — a pass nothing checked.
  // An entry here caps such a control at `partial` with an explicit disclosure
  // instead.
  //
  // Adding an entry requires EVIDENCE that no detector emits the family — a
  // sweep that does not observe it is a lower bound, not proof (SCA families
  // need network access, and some rules need shapes no corpus entry has).
  // Wrongly declaring a live family a gap silently suppresses a control that
  // works, which is the mirror image of the bug this prevents.
};

// FR-501/FR-502 (assurance-hardening PRD, A-07): a `family:` mapping used to
// only count 'critical'/'high' findings as "open" — a control with 50 open
// MEDIUM findings on its mapped family rendered as
// "✓ no open critical/high findings", identical to a genuinely clean
// control. posture/privacy-framework.js already solved the analogous problem
// for its own four-bucket model (its header calls this out directly: a
// vacuous pass is "the same false assurance... arriving by a different
// route"); this raises the floor here to match rather than leaving two
// different standards for what counts as "open" across compliance surfaces.
// A named, ordered rank (not a hardcoded pair of string literals) so a
// future per-framework/per-policy threshold (FR-502's fuller scope) is a
// one-line change here rather than another hunt through the evaluator.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const OPEN_FINDING_MIN_SEVERITY = 'medium';

// FR-502's fuller scope, delivered: "policy-specific rather than globally
// high/critical." An operator can lower (or raise) the open-finding floor
// per framework via .agentic-security/compliance-severity-policy.json:
//   { "default": "medium", "byFramework": { "gdpr": "low" } }
// `default` overrides OPEN_FINDING_MIN_SEVERITY for every framework that
// has no more specific `byFramework` entry; a framework entry wins over
// `default`. Never inferred — an operator decision, same as
// dataflow/privacy-taxonomy.js's (FR-402) taxonomy customization and
// egress/policy.js's (FR-602) config-file precedent. A missing file, a
// malformed one, or a value that is not one of SEVERITY_RANK's five known
// keys all degrade to the built-in 'medium' floor — falling back to a rank
// of `undefined` would make the `>=` comparison always false, silently
// treating EVERY finding as "not open" (the exact vacuous-pass bug this
// threshold exists to prevent), so an invalid override must never reach
// the comparison at all.
const SEVERITY_POLICY_FILE = 'compliance-severity-policy.json';

function _resolveOpenFindingMinSeverity(scanRoot, frameworkId) {
  if (!scanRoot) return OPEN_FINDING_MIN_SEVERITY;
  let raw;
  try {
    raw = fs.readFileSync(statePath(scanRoot, SEVERITY_POLICY_FILE), 'utf8');
  } catch {
    return OPEN_FINDING_MIN_SEVERITY; // ENOENT (the common case) or any other read failure
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    return OPEN_FINDING_MIN_SEVERITY; // malformed config — never throws, never blocks evaluation
  }
  if (!doc || typeof doc !== 'object') return OPEN_FINDING_MIN_SEVERITY;
  const byFramework = (doc.byFramework && typeof doc.byFramework === 'object') ? doc.byFramework : {};
  const candidate = (frameworkId && typeof byFramework[frameworkId] === 'string')
    ? byFramework[frameworkId]
    : (typeof doc.default === 'string' ? doc.default : null);
  return (candidate && Object.prototype.hasOwnProperty.call(SEVERITY_RANK, candidate))
    ? candidate
    : OPEN_FINDING_MIN_SEVERITY;
}

export function evaluateFramework(scanRoot, fw, scan) {
  const minSeverity = _resolveOpenFindingMinSeverity(scanRoot, fw && fw.id);
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
    // FR-PROV-016: findings that contributed an OPEN condition to this
    // control's `family:` mapping(s) — the exact objects `open` below
    // filters to, not just their ids, so deriveComplianceProvenance can read
    // .findingProvenance off them. Naturally empty for a control that ends
    // up 'present' (present requires zero open findings across every
    // mapping) or 'manual' (no family: mapping ever populates it) — so a
    // consumer can treat a non-empty controlRefs as "this control has an
    // attributable gap" without re-deriving the bucket classification.
    const contributingFindings = [];
    let status = 'manual';
    const maps = Array.isArray(c.mapsTo) ? c.mapsTo : [];

    if (maps.length === 0) {
      obs.push('No automated mapping — requires manual evidence collection.');
      let evidence = null;
      try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
      results.push({
        control: c,
        status,
        observations: obs,
        controlRefs: [],
        derivedProvenance: deriveComplianceProvenance([]),
        ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
      });
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
        // No detector produces this family, so its bucket is empty on EVERY
        // scan. Reporting that as "no open findings" is a pass nothing checked
        // — disclose it and cap the control at 'partial' (the same treatment a
        // `rule:` mapping gets, and for the same reason: unverifiable is not
        // evidence). Deliberately does NOT clear allCleared — the control is
        // unknown, not failing.
        if (COMPLIANCE_FAMILY_GAPS[fam]) {
          obs.push(`⚠ ${fam}: no detector can evidence this control (engine-gap) — ${COMPLIANCE_FAMILY_GAPS[fam]}`);
          anySignal = true;
          hasUnverifiableMapping = true;
          continue;
        }
        // Several detectors emit the family as `<family>-<rule-slug>` — the
        // observed vocabulary holds `prompt-injection-http-user-input-in-llm-`,
        // `xpath-injection-query-built-via-string-c` and similar. This lookup
        // used to be an exact Map key read, so `family:prompt-injection`
        // matched none of them and the control read as evidenced whatever the
        // scan found. That silenced LLM01 (Prompt Injection — the FIRST control
        // of the OWASP LLM Top 10), ASVS V5.1 and NIST AI 600-1 MG-3.2-005.
        //
        // The `-` separator is load-bearing, not cosmetic: a bare substring or
        // prefix test would let `nosql-injection` satisfy a `sql-injection`
        // mapping, silently merging two different vulnerability classes. A test
        // pins that boundary in the failing direction.
        const candidates = resolveFamilyKeys(fam, families.keys())
          .flatMap(k => families.get(k) || []);
        const scoped = subfam ? candidates.filter(f => !f.subfamily || f.subfamily === subfam) : candidates;
        const minRank = SEVERITY_RANK[minSeverity];
        const open = scoped.filter(f => !f.intentSuppressed && !f.pastDecision && (SEVERITY_RANK[f.severity] ?? 0) >= minRank);
        if (open.length) {
          allCleared = false;
          contributingFindings.push(...open);
          obs.push(`${open.length} open ${fam} finding(s) at ${minSeverity}+.`);
        } else {
          obs.push(`✓ ${fam}: no open ${minSeverity}+ findings.`);
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
    // PRD F10.3: a control NIST/the framework rates as not code-testable must
    // never read as evidenced by this tool. Two shapes were reaching 'present'
    // that should not have:
    //
    //   codeTestable:'no'      — organisational (policy, training, governance).
    //                            Nothing a scanner observes can satisfy it.
    //   codeTestable:'partial' — the only mappings are `module:` artifact
    //                            EXISTENCE checks. "threat-model.json is
    //                            present" is not evidence that threat modelling
    //                            happened; it is evidence a file exists.
    //
    // Both are capped at 'partial' via the same unverifiable-mapping path a
    // `rule:` mapping already uses, and the reason is stated in the
    // observations so a reader is told WHY rather than left to infer it.
    if (c.codeTestable === 'no') {
      obs.push('⚠ this control is organisational, not code-testable — a scanner cannot evidence it (codeTestable: no).');
      hasUnverifiableMapping = true;
      anySignal = true;
    } else if (c.codeTestable === 'partial' && maps.every(m => !m.startsWith('family:'))) {
      obs.push('⚠ backed only by artifact-existence checks — a present file is weaker evidence than a detector finding nothing (codeTestable: partial).');
      hasUnverifiableMapping = true;
    }

    if (!anySignal) status = 'manual';
    else if (hasUnverifiableMapping) status = 'partial';
    else if (allCleared) status = 'present';
    else if (!anyCleared) status = 'absent';
    else status = 'partial';

    // PRD F10.2: carry the MEASURED strength of the backing detector, so a
    // control mapped to a detector that finds 3 of 18 independent advisories
    // cannot read the same as one backed by a detector that finds nearly
    // everything. Import is lazy so the evaluator keeps working if the bench
    // artifacts are absent (they degrade to `unmeasured`, never to a default).
    let evidence = null;
    try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
    const dedupedRefs = [...new Set(contributingFindings.map((f) => f.id).filter(Boolean))];
    results.push({
      control: c,
      status,
      observations: obs,
      controlRefs: dedupedRefs,
      derivedProvenance: deriveComplianceProvenance(contributingFindings),
      ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
    });
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
  lines.push(`> **This walkthrough organizes scanner evidence into a narrative for an external auditor.** ${EVIDENCE_GRADE_DISCLAIMER_SHORT}`);
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
      if (Array.isArray(ev.controlRefs) && ev.controlRefs.length) {
        lines.push(`**Contributing findings:** ${ev.controlRefs.join(', ')}`);
        const dp = ev.derivedProvenance;
        if (dp && dp.earliestOrigin) {
          const short = String(dp.earliestOrigin.commit || '').slice(0, 7) || 'unknown';
          const day = String(dp.earliestOrigin.authorDate || '').slice(0, 10);
          // Only commit/authorDate/authorName are ever read here — same
          // caveat as deriveComplianceProvenance's earliestOrigin: this
          // object bypasses redactFindingProvenance, so authorEmail must
          // never be surfaced from it without routing through that function
          // first.
          lines.push(`**Earliest proven origin:** ${short} — ${day} — ${dp.earliestOrigin.authorName || 'unknown'} (confidence: ${dp.confidence})`);
        } else if (dp) {
          lines.push(`**Earliest proven origin:** unresolved (confidence: ${dp.confidence})`);
        }
        lines.push('');
      }
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

export const _internals = { _readJson, _resolveOpenFindingMinSeverity, SEVERITY_POLICY_FILE };
