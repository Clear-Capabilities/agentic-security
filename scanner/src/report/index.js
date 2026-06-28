// Report writers — JSON / Markdown / SARIF.
import * as crypto from 'node:crypto';
import { _isCustomSuppressed } from '../engine.js';
import { alertFace, approveFace } from './mascot.js';
import { SCANNER_VERSION } from '../posture/version.js';

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_TO_SARIF = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'none' };

// A short "likely lower risk than its label" note for a high/critical finding the
// reachability / exploitability / confidence pipeline has already marked down.
// Detector severities are hardcoded per rule, so a `critical` can outrun its real
// risk; this surfaces that in the rendered output so the label isn't taken at face
// value. Returns null when the headline severity is fair as-is. (We annotate, not
// mutate — `severity` stays canonical for SARIF/exit codes/baselines.)
function riskNote(f) {
  if (!/^(critical|high)$/.test(String(f.severity || ''))) return null;
  const mv = String(f.mitigationVerdict || '').toLowerCase();
  if (f.unreachable === true || f.unreachableInProd === true || mv.includes('unreachable')) {
    return 'likely lower risk — not reachable in prod';
  }
  if (mv.includes('saniti')) return 'likely lower risk — input appears sanitized';
  const et = String(f.exploitabilityTier || '').toLowerCase();
  if (et === 'minimal' || et === 'low') return `likely lower risk — ${et} exploitability`;
  const ct = String(f.confidenceTier || '').toLowerCase();
  if (ct === 'low' || (typeof f.confidence === 'number' && f.confidence > 0 && f.confidence < 0.5)) {
    return 'lower confidence — verify before prioritising';
  }
  return null;
}

function fingerprint(f){
  const s = `${f.file}:${f.line||f.source?.line||0}:${f.vuln||f.type||''}`;
  return crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
}

export function normalizeFindings(scan){
  const out = [];
  // Feat-4: filter findings via custom suppressions, recording the suppression
  // in scan.suppressions so it shows up under --include-suppressed.
  const suppress = (vuln, file, line, snippet) => {
    const sup = _isCustomSuppressed(vuln, file || '');
    if (!sup) return false;
    (scan.suppressions = scan.suppressions || []).push({
      vuln, file, line, snippet: snippet || '',
      reason: 'custom-rule:' + (sup.reason || 'rule.yml suppression'),
    });
    return true;
  };
  for (const f of (scan.findings||[])) {
    if (suppress(f.vuln || f.type, f.file, f.line || f.source?.line || 0, f.snippet)) continue;
    out.push({
      id: f.id || fingerprint(f),
      kind: f.isCrossFile ? 'sast' : (f.kind || 'sast'),
      severity: f.severity || 'medium',
      vuln: f.vuln || f.type,
      cwe: f.cwe || null,
      owaspLlm: f.owaspLlm || null,
      stride: f.stride || null,
      file: f.file,
      line: f.line || f.source?.line || f.sink?.line || 0,
      snippet: f.snippet || f.source?.snippet || f.sink?.snippet || '',
      fix: f.fix ? { description: f.fix, code: f.code || '' } : null,
      reachable: f.reachable ?? null,
      triage: f.triageScore ?? null,
      dataClasses: f.dataClasses || [],
      chain: Array.isArray(f.chain) ? f.chain : null,
      confidence: typeof f.confidence === 'number' ? f.confidence : null,
      // R17: corroboration ("one issue, many signals") — count of independent
      // analyses that agreed, and which ones.
      corroborationCount: typeof f.corroborationCount === 'number' ? f.corroborationCount : null,
      corroboration: f.corroboration || null,
      multiSignal: f.multiSignal === true ? true : null,
      // R13: proof verdict — `provablySafe` means a flow proof discharged this
      // finding (parameterizer on every path / sanitizer excludes metachars).
      proof: f.proof || null,
      provablySafe: f.provablySafe === true ? true : null,
      // 0.6.0 Feat-2
      toxicity: f.toxicityScore ?? null,
      toxicityFactors: f.toxicityFactors || null,
      toxicityLabel: f.toxicityLabel || null,
      sources: Array.isArray(f.sources) && f.sources.length ? f.sources : null,
      epssScore: f.epssScore ?? null,
      epssPercentile: f.epssPercentile ?? null,
      epssCve: f.epssCve || null,
      exploitedNow: f.exploitedNow === true,
      tags: Array.isArray(f.tags) && f.tags.length ? f.tags : null,
      blastRadius: f.blastRadius || null,
      // Sentinel-parity (FR-PREC, FR-L3) preserved fields.
      stableId: f.stableId || null,
      confidenceTier: f.confidenceTier || null,
      exploitability: typeof f.exploitability === 'number' ? f.exploitability : null,
      exploitabilityTier: f.exploitabilityTier || null,
      exploitabilityFactors: Array.isArray(f.exploitabilityFactors) ? f.exploitabilityFactors : null,
      clusterSize: typeof f.clusterSize === 'number' ? f.clusterSize : null,
      unreachable: f.unreachable === true,
      validator_verdict: f.validator_verdict || null,
      llm_confidence: typeof f.llm_confidence === 'number' ? f.llm_confidence : null,
      unvalidated: f.unvalidated === true,
      cross_language: f.cross_language === true,
      family: f.family || null,
      // Premortem #8: surface the parser field so downstream consumers
      // (UI, SARIF, calibration) see the value the engine backfilled.
      parser: f.parser || null,
      // Premortem 3R-6 + 4R-10: audit-provenance fields. Collapse the two
      // bool flags into one tri-state `signatureStatus` so consumers don't
      // have to know that passThroughSigning supersedes unsigned. The legacy
      // flags are kept on the normalized finding for one release of grace.
      _unsigned: f._unsigned === true,
      _passThroughSigning: f._passThroughSigning === true,
      signatureStatus: f._passThroughSigning ? 'pass-through' : (f._unsigned ? 'unsigned' : 'verified'),
      // Phase-1 next-gen P1.1 (FR-VER-2): generated PoC, or null if the CWE
      // family has no template in v1. `poc.code` is the runnable script;
      // `poc.runHint` is the suggested invocation (e.g. `node poc.mjs`).
      regression_test: f.regression_test && typeof f.regression_test === 'object' ? {
        lang: f.regression_test.lang || null,
        framework: f.regression_test.framework || null,
        filename: f.regression_test.filename || null,
        runHint: f.regression_test.runHint || null,
        code: typeof f.regression_test.code === 'string' ? f.regression_test.code : null,
      } : null,
      poc: f.poc && typeof f.poc === 'object' ? {
        lang: f.poc.lang || null,
        kind: f.poc.kind || null,
        cwe: f.poc.cwe || null,
        family: f.poc.family || null,
        runHint: f.poc.runHint || null,
        code: typeof f.poc.code === 'string' ? f.poc.code : null,
        // Harness-engineering: surface inference confidence so verifiers and
        // regression-test-gen consumers can refuse to run low-confidence ones.
        paramKey: f.poc.paramKey || null,
        paramKeyConfidence: f.poc.paramKeyConfidence || null,
        paramKeyInferred: typeof f.poc.paramKeyInferred === 'boolean' ? f.poc.paramKeyInferred : null,
      } : null,
      // Phase-1 next-gen P1.3 (FR-UX-1, FR-UX-2): calibrated probability +
      // 95% Wilson CI + sample size. Null when N < MIN_SAMPLES_FOR_CALIBRATION
      // for this family; `calibration_reason` explains why.
      calibrated_confidence: typeof f.calibrated_confidence === 'number' ? f.calibrated_confidence : null,
      calibrated_confidence_ci: Array.isArray(f.calibrated_confidence_ci) ? f.calibrated_confidence_ci : null,
      calibrated_n: typeof f.calibrated_n === 'number' ? f.calibrated_n : 0,
      calibration_reason: f.calibration_reason || null,
      // Phase-1 next-gen P1.2 (FR-VER-6): verifier verdict.
      verifier_verdict: f.verifier_verdict || null,
      verifier_reason: f.verifier_reason || null,
      verifier_runner: f.verifier_runner || null,
      narration: typeof f.narration === 'string' ? f.narration : null,
      // v3 next-gen — Pillars 8 (Adversary Simulation) + 9 (Production-Aware
      // Reasoning) + spec/clone/ai/why-fired property bag.
      mitigationVerdict: f.mitigationVerdict || null,
      mitigationsApplied: Array.isArray(f.mitigationsApplied) ? f.mitigationsApplied : null,
      mitigatedByWaf: f.mitigatedByWaf === true,
      wafRuleId: f.wafRuleId || null,
      mitigatedByAuth: f.mitigatedByAuth === true,
      authMechanism: f.authMechanism || null,
      mitigatedByNetwork: f.mitigatedByNetwork === true,
      networkExposure: f.networkExposure || null,
      featureFlag: f.featureFlag || null,
      featureFlagState: f.featureFlagState || null,
      featureFlagRollout: typeof f.featureFlagRollout === 'number' ? f.featureFlagRollout : null,
      exposedInProd: f.exposedInProd === true,
      unreachableInProd: f.unreachableInProd === true,
      coldPath: f.coldPath === true,
      hotPath: f.hotPath === true,
      prodRequestCount: typeof f.prodRequestCount === 'number' ? f.prodRequestCount : null,
      crownJewelScore: typeof f.crownJewelScore === 'number' ? f.crownJewelScore : null,
      crownJewelTier: f.crownJewelTier || null,
      crownJewelFactors: Array.isArray(f.crownJewelFactors) ? f.crownJewelFactors : null,
      cloneClusterId: f.cloneClusterId || null,
      cloneClusterSize: typeof f.cloneClusterSize === 'number' ? f.cloneClusterSize : null,
      provenance: f.provenance || null,
      provenanceScore: typeof f.provenanceScore === 'number' ? f.provenanceScore : null,
      typeNarrowed: f.typeNarrowed || null,
      strideCategory: f.strideCategory || null,
      personaScores: f.personaScores || null,
      personaTopTwo: Array.isArray(f.personaTopTwo) ? f.personaTopTwo : null,
      personaMaxName: f.personaMaxName || null,
      personaMaxScore: typeof f.personaMaxScore === 'number' ? f.personaMaxScore : null,
      reverseExposure: f.reverseExposure || null,
      specMined: f.specMined || null,
      whyFired: f.whyFired || null,
      adversaryTranscript: f.adversaryTranscript || null,
      // v3 next-gen — bounty + playbook fields.
      predictedBountyUsd: f.predictedBountyUsd || null,
      bountyConfidence: f.bountyConfidence || null,
      attackPlaybook: f.attackPlaybook || null,
    });
  }
  for (const s of (scan.secrets||[])) {
    if (suppress(s.vuln || 'Hardcoded Secret', s.file, s.line, s.snippet)) continue;
    out.push({
      id: s.id || fingerprint(s),
      kind: 'secret',
      severity: s.severity || 'high',
      vuln: s.vuln || 'Hardcoded Secret',
      cwe: s.cwe || 'CWE-798',
      stride: s.stride || 'Information Disclosure',
      file: s.file, line: s.line, snippet: s.snippet || '',
      masked: s.masked || null,
      fix: s.fix ? { description: s.fix, code: s.code || '' } : null,
      blastRadius: s.blastRadius || null,
      // Premortem #8: parser/family for downstream confidence + calibration.
      parser: s.parser || 'SECRETS',
      family: s.family || 'hardcoded-secret',
    });
  }
  for (const lv of (scan.logicVulns||[])) {
    if (suppress(lv.vuln, lv.file, lv.line, lv.snippet)) continue;
    out.push({
      id: lv.id || fingerprint(lv),
      kind: lv.kind || 'logic',
      severity: lv.severity || 'medium',
      vuln: lv.vuln,
      cwe: lv.cwe || null,
      stride: lv.stride || null,
      file: lv.file, line: lv.line, snippet: lv.snippet || '',
      fix: lv.fix ? { description: lv.fix, code: lv.code || '' } : null,
      blastRadius: lv.blastRadius || null,
      // Premortem #8.
      parser: lv.parser || 'LOGIC',
      family: lv.family || null,
    });
  }
  for (const sc of (scan.supplyChain||[])) {
    const scVuln = sc.vuln || sc.advisory || 'Vulnerable Dependency';
    const scFile = sc.filePath || sc.file || 'package.json';
    if (suppress(scVuln, scFile, 0, sc.description || '')) continue;
    out.push({
      id: fingerprint(sc),
      kind: 'sca',
      severity: sc.severity || 'high',
      vuln: scVuln,
      cwe: sc.cwe || null,
      stride: null,
      file: scFile,
      line: 0,
      // Premortem #8.
      parser: 'SCA',
      family: 'vulnerable-dep',
      ecosystem: sc.ecosystem,
      package: sc.name,
      version: sc.version,
      cveAliases: sc.cveAliases || [],
      osvId: sc.osvId || null,
      advisory: sc.advisory || sc.description || '',
      fixedIn: sc.range || null,
      // Feat-9: real-world risk signals
      epssScore: sc.epssScore ?? null,
      epssPercentile: sc.epssPercentile ?? null,
      epssCve: sc.epssCve || null,
      exploitedNow: sc.exploitedNow === true,
      tags: Array.isArray(sc.tags) && sc.tags.length ? sc.tags : null,
      blastRadius: sc.blastRadius || null,
      cvssVector: sc.cvssVector || null,
      functionReachable: sc.functionReachable || null,
      // 0.10.0: CISA KEV — actively abused in the wild
      kev: sc.kev === true,
      kevDateAdded: sc.kevDateAdded || null,
      kevRansomware: sc.kevRansomware === true,
      weaponized: sc.weaponized === true,
      // 0.6.0 Feat-2: toxicity score
      toxicity: sc.toxicityScore ?? null,
      toxicityFactors: sc.toxicityFactors || null,
      toxicityLabel: sc.toxicityLabel || null,
    });
  }
  // Sort by severity tier, then within a tier by EPSS percentile (desc) so that
  // CVEs with active in-the-wild abuse float above theoretical CVEs.
  return out.sort((a, b) => {
    const sevDiff = (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    const ae = a.epssPercentile ?? -1;
    const be = b.epssPercentile ?? -1;
    return be - ae;
  });
}

// Feat-5: group findings that share a likely root cause so the fixer subagent
// can patch the helper once instead of N call sites. Heuristic: same vuln type,
// same sink "type" (Database Query, OS Command, etc.), and ≥80% overlap of
// usedVars across the group.
export function bundleFindingsByRootCause(findings){
  const bundles = [];
  const remaining = [];
  // Bucket by (vuln, sinkType)
  const buckets = new Map();
  for (const f of findings) {
    const sinkType = f.sink?.type || f.kind || 'unknown';
    const key = `${f.vuln}::${sinkType}`;
    (buckets.get(key) || buckets.set(key, []).get(key)).push(f);
  }
  for (const [key, group] of buckets) {
    if (group.length < 3) { remaining.push(...group); continue; }
    // Need actual usedVars to compare — only the SAST sink path has these
    const withVars = group.filter(f => Array.isArray(f.sink?.usedVars) && f.sink.usedVars.length);
    if (withVars.length < 3) { remaining.push(...group); continue; }
    // Use the most common var across the group as the bundle key
    const tally = new Map();
    for (const f of withVars) for (const v of f.sink.usedVars) tally.set(v, (tally.get(v) || 0) + 1);
    let bestVar = null, bestCount = 0;
    for (const [v, c] of tally) if (c > bestCount && c >= Math.ceil(withVars.length * 0.8)) { bestVar = v; bestCount = c; }
    if (!bestVar) { remaining.push(...group); continue; }
    const children = withVars.filter(f => f.sink.usedVars.includes(bestVar));
    if (children.length < 3) { remaining.push(...group); continue; }
    const [vuln, sinkType] = key.split('::');
    const bundleId = `bundle:${bestVar}:${vuln.replace(/\s/g, '_')}`;
    for (const c of children) c.bundleId = bundleId;
    bundles.push({
      bundleId, vuln, sinkType,
      sharedHelper: bestVar,
      childCount: children.length,
      childIds: children.map(c => c.id || `${c.file}:${c.line || c.source?.line || 0}`),
      severity: children[0].severity,
      cwe: children[0].cwe,
      summary: `${children.length} ${vuln} findings share \`${bestVar}\`. Refactor at the helper for one patch, ${children.length} resolutions.`,
    });
    // Keep all children in the remaining list too — they still appear individually
    // with bundleId set, but the bundle entry surfaces the root-cause story.
    remaining.push(...group);
  }
  return { bundles, findings: remaining };
}

export function toJSON(scan, meta={}, opts={}){
  const findings = normalizeFindings(scan);
  // Feat-5: surface root-cause bundles alongside individual findings.
  // Each child finding now has bundleId set so the fixer subagent can
  // detect "this is one of N findings that share a helper".
  const { bundles } = bundleFindingsByRootCause(findings.map(f => {
    // Pull sink.usedVars off the original raw finding (lost during normalize)
    const raw = (scan.findings || []).find(r => (r.id || '') === f.id);
    return raw?.sink ? { ...f, sink: raw.sink } : f;
  }));
  const out = {
    scanId: meta.scanId || crypto.randomUUID(),
    startedAt: meta.startedAt || new Date().toISOString(),
    durationMs: meta.durationMs || 0,
    scanned: { files: scan.filesScanned||0, lines: scan.linesScanned||0 },
    findings,
    bundles,
    routes: scan.routes || [],
    components: (scan.components||[]).map(c=>({
      ecosystem: c.ecosystem, name: c.name, version: c.version,
      reachable: c.reachable, hasVulns: c.hasVulns, isDeprecated: c.isDeprecated,
      latestVersion: c.latestVersion, license: c.license,
    })),
    suppressedCount: (scan.suppressions||[]).length,
    blastRadiusSignals: scan.blastRadiusSignals || null,
    // v3 next-gen — scan-level reports (counterfactual SPOF list, threat model
    // summary, trust-boundary Mermaid, calibration-drift alarms).
    _v3: scan._v3 || null,
    // Harness-engineering (post-derived): annotator-pipeline errors. Empty
    // array means clean; entries here mean one or more posture annotators
    // threw and were skipped. The findings still ship; downstream consumers
    // see the gap.
    annotatorErrors: Array.isArray(scan.annotatorErrors) ? scan.annotatorErrors : [],
    _scanMeta: scan._scanMeta || null,
  };
  if (opts.includeSuppressed) out.suppressed = scan.suppressions||[];
  return out;
}

// R2: Always-on CSV writer for pro mode. One row per finding, columns chosen
// for spreadsheet/Excel/BigQuery import.
// STIX 2.1 emit (FR-SDLC-5). One Vulnerability + Indicator SDO pair per
// finding, wrapped in a single Bundle. Lets threat-intel platforms consume
// the scanner output natively. Spec: https://docs.oasis-open.org/cti/stix/v2.1/
import { randomUUID, createHash } from 'node:crypto';

function _stixId(type, finding) {
  // Deterministic UUID: derive from sha256(stableId||vuln||file||line) so
  // re-runs produce stable ids per finding.
  const seed = `${finding.stableId || ''}::${finding.vuln || ''}::${finding.file || ''}::${finding.line || ''}`;
  const h = createHash('sha256').update(seed).digest('hex');
  // Format as UUIDv4-shaped (8-4-4-4-12).
  const u = `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
  return `${type}--${u}`;
}

export function toSTIX(scan, meta = {}) {
  const findings = normalizeFindings(scan);
  const now = (meta.startedAt && new Date(meta.startedAt).toISOString()) || new Date().toISOString();
  const objects = [];
  for (const f of findings) {
    const vulnId = _stixId('vulnerability', f);
    const indId  = _stixId('indicator',     f);
    const cweExt = f.cwe ? [{
      source_name: 'cwe',
      external_id: String(f.cwe),
      url: `https://cwe.mitre.org/data/definitions/${String(f.cwe).replace(/[^0-9]/g, '')}.html`,
    }] : [];
    objects.push({
      type: 'vulnerability',
      spec_version: '2.1',
      id: vulnId,
      created: now,
      modified: now,
      name: `${f.vuln || 'Security finding'} at ${f.file || '?'}:${f.line || '?'}`,
      description: f.fix?.description || f.vuln || '',
      external_references: cweExt,
      labels: [f.severity || 'unknown'],
      // x_* extension fields — STIX 2.1 allows custom properties prefixed
      // with x_ for tool-specific data.
      x_severity: f.severity || 'unknown',
      x_confidence: typeof f.confidence === 'number' ? f.confidence : null,
      x_calibrated_confidence: typeof f.calibrated_confidence === 'number' ? f.calibrated_confidence : null,
      x_calibrated_ci: Array.isArray(f.calibrated_confidence_ci) ? f.calibrated_confidence_ci : null,
      x_exploitability: typeof f.exploitability === 'number' ? f.exploitability : null,
      x_verifier_verdict: f.verifier_verdict || null,
      x_stable_id: f.stableId || null,
      x_family: f.family || null,
    });
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: indId,
      created: now,
      modified: now,
      indicator_types: ['vulnerable'],
      name: `${f.vuln || 'Security finding'} signature`,
      pattern: `[file:name = '${(f.file || '').replace(/'/g, "\\'")}']`,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: now,
      // Link to the vulnerability via a relationship object below.
    });
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: _stixId('relationship', { ...f, vuln: 'relationship:' + (f.vuln || '') }),
      created: now,
      modified: now,
      relationship_type: 'indicates',
      source_ref: indId,
      target_ref: vulnId,
    });
  }
  return {
    type: 'bundle',
    id: `bundle--${randomUUID()}`,
    objects,
  };
}

export function toCSV(scan){
  const findings = normalizeFindings(scan);
  const esc = v => {
    if (v == null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const header = ['id', 'severity', 'vuln', 'cwe', 'cvss', 'owasp', 'file', 'line', 'confidence', 'reachable', 'kind', 'snippet'];
  const rows = [header.join(',')];
  for (const f of findings) {
    rows.push([
      esc(f.id), esc(f.severity), esc(f.vuln), esc(f.cwe), esc(f.cvss || ''),
      esc(f.owasp || ''), esc(f.file), esc(f.line),
      esc(f.confidence == null ? '' : f.confidence.toFixed(3)),
      esc(f.reachable == null ? '' : f.reachable),
      esc(f.kind), esc((f.snippet || '').slice(0, 200)),
    ].join(','));
  }
  return rows.join('\n');
}

// JUnit XML output — for CI test-report aggregators (Jenkins, GitLab, CircleCI).
// Each finding becomes one <testcase> with a <failure> child. The whole report
// is one <testsuite> wrapped in <testsuites>.
export function toJUnit(scan, meta={}){
  const findings = normalizeFindings(scan);
  const esc = v => {
    if (v == null) return '';
    return String(v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  };
  const escCdata = v => String(v == null ? '' : v).replace(/]]>/g, ']]]]><![CDATA[>');
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
  const failures = findings.length;
  const ts = meta.startedAt || new Date().toISOString();
  const lines = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<testsuites name="agentic-security" tests="${failures}" failures="${failures}" timestamp="${esc(ts)}">`);
  lines.push(`  <testsuite name="agentic-security" tests="${failures}" failures="${failures}" timestamp="${esc(ts)}">`);
  for (const f of findings) {
    const classname = esc(f.cwe || f.kind || 'finding');
    const name = esc(`${f.file || '?'}:${f.line || 0} ${f.vuln || ''}`.trim());
    const failType = esc(f.severity || 'medium');
    const failMsg = esc(f.vuln || 'finding');
    const body = [
      `severity: ${f.severity || 'medium'}`,
      f.cwe ? `cwe: ${f.cwe}` : null,
      `file: ${f.file || '?'}:${f.line || 0}`,
      f.snippet ? `snippet: ${f.snippet}` : null,
      f.fix?.description ? `\nremediation: ${f.fix.description}` : null,
      f.fix?.code ? `\nfix:\n${f.fix.code}` : null,
    ].filter(Boolean).join('\n');
    lines.push(`    <testcase classname="${classname}" name="${name}">`);
    lines.push(`      <failure type="${failType}" message="${failMsg}"><![CDATA[${escCdata(body)}]]></failure>`);
    lines.push(`    </testcase>`);
  }
  lines.push('  </testsuite>');
  lines.push('</testsuites>');
  return lines.join('\n');
}

export function toMarkdown(scan, meta={}){
  const findings = normalizeFindings(scan);
  const lines = ['# Agentic Security — Scan Report', ''];
  lines.push(`**Files scanned:** ${scan.filesScanned||0}    **Findings:** ${findings.length}    **Generated:** ${meta.startedAt||new Date().toISOString()}`);
  lines.push('');
  const bySev = {};
  for (const f of findings) (bySev[f.severity] ||= []).push(f);
  // Premortem 4R-11: include a Validator column when at least one finding
  // carries a verdict, so SCA findings tagged 'not-applicable' aren't
  // invisible to a reader looking only at the report.
  const showValidator = findings.some(f => f.validator_verdict);
  for (const sev of ['critical','high','medium','low','info']) {
    if (!bySev[sev]) continue;
    lines.push(`## ${sev.toUpperCase()} (${bySev[sev].length})`);
    lines.push('');
    if (showValidator) {
      lines.push('| File:Line | Vulnerability | CWE | EPSS | Validator | Fix |');
      lines.push('|---|---|---|---|---|---|');
    } else {
      lines.push('| File:Line | Vulnerability | CWE | EPSS | Fix |');
      lines.push('|---|---|---|---|---|');
    }
    for (const f of bySev[sev]) {
      const fix = f.fix?.description || '';
      const epss = f.epssScore != null ? `${Math.round(f.epssScore*100)}%` : '—';
      if (showValidator) {
        const v = f.validator_verdict || '—';
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${v} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      } else {
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      }
    }
    lines.push('');
  }
  return lines.join('\n');
}

export function toSARIF(scan, meta={}){
  const findings = normalizeFindings(scan);
  const ruleMap = new Map();
  for (const f of findings) if (f.vuln && !ruleMap.has(f.vuln)) ruleMap.set(f.vuln, {
    id: f.vuln.replace(/[^a-zA-Z0-9]/g, '_'),
    name: f.vuln,
    shortDescription: { text: f.vuln },
    fullDescription: { text: f.fix?.description || f.vuln },
    helpUri: f.cwe ? `https://cwe.mitre.org/data/definitions/${f.cwe.replace(/[^0-9]/g,'')}.html` : undefined,
    properties: { tags: [f.cwe, f.stride].filter(Boolean) },
  });
  // Premortem 2R1.1 / 2R5.3 / 2R-12: surface the load-bearing caveats in the
  // SARIF run itself so machine consumers see them. Without these, a CI that
  // ingests SARIF treats "confidence: 0.9" as a probability and the
  // benchmark-tuned 0.907 number as quality evidence.
  const SARIF_NOTIFICATIONS = [
    {
      id: 'scores-are-ordinal',
      name: 'ScoresAreOrdinal',
      shortDescription: { text: 'priority/exploitability scores are ordinal, not calibrated probabilities' },
      defaultConfiguration: { level: 'note' },
      fullDescription: { text: 'The properties.exploitability and properties.confidence fields on each result are ORDINAL priority scores used to rank findings within a scan. They are NOT calibrated probabilities; do not render them as percentages or feed them into pricing / risk-acceptance decisions. Use the tier labels (critical/high/medium/low) for coarse bucketing. See bench/README.md for the open calibration work.' },
    },
    {
      id: 'owasp-benchmark-tuning',
      name: 'OwaspBenchmarkTuning',
      shortDescription: { text: 'engine ships OWASP-Benchmark-shape precision lifters; F1 numbers do not generalize' },
      defaultConfiguration: { level: 'note' },
      fullDescription: { text: 'The engine includes precision lifters (sast/primary-cwe-java.js, sast/java-constant-fold.js) whose heuristics are tuned to OWASP Benchmark v1.2 file shape (servlet-style files <=300 LoC, canonical variable names). F1 numbers cited against OWASP Benchmark do NOT generalize to arbitrary Java code. Expect higher FP rates on real-world codebases until per-customer tuning lands. See bench/README.md.' },
    },
  ];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'agentic-security', version: SCANNER_VERSION, informationUri: 'https://github.com/Clear-Capabilities/agentic-security', rules: [...ruleMap.values()], notifications: SARIF_NOTIFICATIONS }},
      invocations: [{
        executionSuccessful: true,
        toolExecutionNotifications: SARIF_NOTIFICATIONS.map(n => ({
          descriptor: { id: n.id }, level: 'note',
          message: { text: n.fullDescription.text.slice(0, 1000) },
        })),
        // Premortem 3R-6: surface the ruleset-version stamp at SARIF level so
        // /security-trend regression analysis can attribute deltas to rule
        // changes vs. code changes.
        properties: {
          ...(scan && scan._rulesetVersion ? { rulesetVersion: scan._rulesetVersion } : {}),
          ...(scan && scan._rulesetVersionSource ? { rulesetVersionSource: scan._rulesetVersionSource } : {}),
          ...(scan && scan._rulesetVersionMismatch ? { rulesetVersionMismatch: scan._rulesetVersionMismatch } : {}),
        },
      }],
      results: findings.map(f => {
        const chain = Array.isArray(f.chain) ? f.chain : [];
        const codeFlows = chain.length >= 2 ? [{
          threadFlows: [{
            locations: chain.map((hop, idx) => ({
              location: {
                physicalLocation: {
                  artifactLocation: { uri: hop.file || f.file },
                  region: { startLine: Math.max(1, hop.line || 1) },
                },
                message: { text: hop.label || (idx === 0 ? 'source' : idx === chain.length - 1 ? 'sink' : 'propagation') },
              },
            })),
          }],
        }] : undefined;
        const fixes = f.remediation ? [{
          description: { text: f.remediation.slice(0, 500) },
        }] : undefined;
        return {
        ruleId: f.vuln ? f.vuln.replace(/[^a-zA-Z0-9]/g, '_') : 'unknown',
        level: SEV_TO_SARIF[f.severity] || 'warning',
        message: { text: f.fix?.description || f.vuln || 'Security finding' },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, f.line||1) } } }],
        ...(codeFlows ? { codeFlows } : {}),
        ...(fixes ? { fixes } : {}),
        // Phase-1 (Sentinel-parity) fingerprint: stableId persists across
        // refactors. Keep partialFingerprints intact for tools that key on
        // the line-hash; add a 'stableId' fingerprint for tools that respect
        // the SARIF stable-fingerprint convention.
        partialFingerprints: {
          primaryLocationLineHash: f.id,
          ...(f.stableId ? { stableId: f.stableId } : {}),
        },
        // Sentinel-parity SARIF extensions — namespaced under 'properties'.
        properties: {
          ...(typeof f.confidence === 'number' ? { confidence: f.confidence } : {}),
          ...(f.confidenceTier ? { confidenceTier: f.confidenceTier } : {}),
          ...(typeof f.exploitability === 'number' ? { exploitability: f.exploitability } : {}),
          ...(f.exploitabilityTier ? { exploitabilityTier: f.exploitabilityTier } : {}),
          ...(Array.isArray(f.exploitabilityFactors) ? { exploitabilityFactors: f.exploitabilityFactors } : {}),
          ...(typeof f.clusterSize === 'number' ? { clusterSize: f.clusterSize } : {}),
          ...(f.unreachable ? { unreachable: true } : {}),
          ...(f.validator_verdict ? { validatorVerdict: f.validator_verdict } : {}),
          ...(typeof f.llm_confidence === 'number' ? { llmConfidence: f.llm_confidence } : {}),
          ...(f.unvalidated ? { unvalidated: true } : {}),
          ...(f.cross_language ? { crossLanguage: true } : {}),
          ...(f.family ? { family: f.family } : {}),
          // Premortem 3R-6 + 4R-10: emit the single signatureStatus tri-state
          // (verified | unsigned | pass-through). The legacy bool flags are
          // emitted alongside for one release of grace so existing dashboards
          // don't break; new integrations should switch to signatureStatus.
          signatureStatus: f.signatureStatus || (f._passThroughSigning ? 'pass-through' : (f._unsigned ? 'unsigned' : 'verified')),
          ...(f._unsigned ? { unsigned: true } : {}),
          ...(f._passThroughSigning ? { passThroughSigning: true } : {}),
        },
      };}),
    }],
  };
}

// Feat-8: Interactive HTML report — single self-contained file with no external
// resources (no CDN, no Google Fonts, no remote JS). Filterable by severity / kind
// / CWE; per-finding code snippet panel; STRIDE heatmap; hotspot file ranking.
function _esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// R11 (PRD §5) — OpenVEX export. Turns our reachability verdict (R7/R12) into a
// standard interchange statement per CVE: unreachable tiers → not_affected with
// the `vulnerable_code_not_in_execute_path` justification; reachable tiers →
// affected with an action statement; unknown → under_investigation. Lets
// downstream tools and auditors inherit "this CVE can't fire here" in a format
// they accept, instead of re-triaging our transitive noise.
const _VEX_REACHABLE = new Set(['route-reachable-via-function', 'function-reachable', 'import-reachable']);
const _VEX_NOT_AFFECTED = new Set(['unreachable', 'build-only', 'manifest-only', 'transitive-only']);
export function toVex(scan, meta = {}) {
  const deps = (scan.supplyChain || []).filter(s => s && s.type === 'vulnerable_dep');
  const statements = [];
  for (const s of deps) {
    const cves = (Array.isArray(s.cveAliases) && s.cveAliases.length ? s.cveAliases : [s.osvId]).filter(Boolean);
    if (!cves.length) continue;
    const purl = s.purl || `pkg:${s.ecosystem || 'generic'}/${s.name}@${s.version || '0'}`;
    const stmt = {};
    if (_VEX_NOT_AFFECTED.has(s.reachabilityTier)) {
      stmt.status = 'not_affected';
      stmt.justification = 'vulnerable_code_not_in_execute_path';
      stmt.impact_statement = `agentic-security reachability: ${s.reachabilityTier}`;
    } else if (_VEX_REACHABLE.has(s.reachabilityTier)) {
      stmt.status = 'affected';
      stmt.action_statement = s.scaVerdictReason || s.remediation ||
        (Array.isArray(s.fixedVersions) && s.fixedVersions.length ? `upgrade ${s.name} to ${s.fixedVersions[0]}` : 'review and remediate');
    } else {
      stmt.status = 'under_investigation';
    }
    for (const cve of cves) {
      statements.push({ vulnerability: { name: cve }, products: [{ '@id': purl }], ...stmt });
    }
  }
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://agentic-security/vex/${(meta && meta.scanId) || 'scan'}`,
    author: 'agentic-security',
    timestamp: (meta && meta.startedAt) || new Date().toISOString(),
    version: 1,
    statements,
  };
}

export function toHTML(scan, meta = {}) {
  // Attach the "likely lower risk" note (computed server-side) so the browser
  // render can badge over-stated high/critical findings.
  const findings = normalizeFindings(scan).map(f => ({ ...f, _riskNote: riskNote(f) }));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const stride = {};
  for (const f of findings) if (f.stride) stride[f.stride] = (stride[f.stride] || 0) + 1;
  const byFile = {};
  for (const f of findings) byFile[f.file] = (byFile[f.file] || 0) + 1;
  const hotspots = Object.entries(byFile).sort((a,b)=>b[1]-a[1]).slice(0, 10);
  const data = JSON.stringify(findings).replace(/</g, '\\u003c');
  const generatedAt = new Date().toISOString();
  const SEV_HEX = { critical: '#ff2d55', high: '#ff6b35', medium: '#ffb800', low: '#34d058', info: '#82aaff' };
  const sevBars = Object.entries(counts).map(([k, v]) =>
    `<div class="sev-row"><span class="sev-tag" style="background:${SEV_HEX[k]}22;color:${SEV_HEX[k]}">${k}</span><span class="sev-bar" style="width:${Math.min(100, v * 4)}%;background:${SEV_HEX[k]}"></span><span class="sev-num">${v}</span></div>`
  ).join('');
  const strideRows = ['Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege']
    .map(s => `<tr><td>${_esc(s)}</td><td class="num">${stride[s] || 0}</td></tr>`).join('');
  const hotRows = hotspots.map(([f, n]) => `<tr><td><code>${_esc(f)}</code></td><td class="num">${n}</td></tr>`).join('');
  const SECTIONS = [
    { kind: 'iac',    label: 'IaC',     color: '#ffb800', icon: '🏗️' },
    { kind: 'logic',  label: 'Logic',   color: '#a78bfa', icon: '⚙️' },
    { kind: 'sast',   label: 'SAST',    color: '#38bdf8', icon: '🔍' },
    { kind: 'sca',    label: 'SCA',     color: '#34d058', icon: '📦' },
    { kind: 'secret', label: 'Secrets', color: '#f97316', icon: '🔑' },
  ];
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>agentic-security — scan report</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;padding:0;font:14px/1.5 -apple-system,system-ui,sans-serif;background:#0b1020;color:#e2e8f4}
  header{padding:24px 32px;border-bottom:1px solid #1e293b;background:#0f172a}
  h1{margin:0 0 4px 0;font-size:22px;font-weight:600}
  .meta{color:#64748b;font-size:13px}
  main{padding:24px 32px}
  .grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:24px;margin-bottom:24px}
  .card{background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:16px}
  .card h2{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#94a3b8;margin:0 0 12px 0}
  .sev-row{display:flex;align-items:center;gap:12px;margin-bottom:6px;font-size:12px}
  .sev-tag{padding:2px 8px;border-radius:3px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;min-width:64px;text-align:center}
  .sev-bar{height:6px;border-radius:3px;flex:1}
  .sev-num{min-width:32px;text-align:right;color:#94a3b8;font-variant-numeric:tabular-nums}
  table{width:100%;border-collapse:collapse;font-size:12px}
  table td{padding:6px 8px;border-bottom:1px solid #1e293b}
  table .num{text-align:right;color:#94a3b8;font-variant-numeric:tabular-nums}
  table code{font-family:ui-monospace,SFMono-Regular,monospace;font-size:11px;color:#e2e8f4}
  .filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
  .filters input,.filters select{padding:6px 10px;background:#0f172a;border:1px solid #1e293b;border-radius:4px;color:#e2e8f4;font:13px/1 -apple-system,system-ui,sans-serif}
  .btn{padding:5px 12px;background:#1e293b;border:1px solid #334155;border-radius:4px;color:#94a3b8;font:12px/1 -apple-system,system-ui,sans-serif;cursor:pointer;white-space:nowrap}
  .btn:hover{background:#273549;color:#e2e8f4}
  .section{margin-bottom:28px}
  .section-header{display:flex;align-items:center;gap:10px;margin-bottom:10px;cursor:pointer;user-select:none}
  .section-title{font-size:15px;font-weight:700;letter-spacing:0.02em}
  .section-count{font-size:12px;color:#94a3b8;background:#1e293b;padding:2px 8px;border-radius:10px;font-variant-numeric:tabular-nums}
  .section-toggle{color:#475569;font-size:11px;margin-left:auto}
  .section-body{display:flex;flex-direction:column;gap:8px}
  .section-body.collapsed{display:none}
  .section-empty{color:#475569;font-size:13px;font-style:italic;padding:8px 0}
  .f{background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:12px 16px;cursor:pointer}
  .f.expanded{border-color:#38bdf8}
  .f-head{display:flex;align-items:center;gap:12px;font-size:13px}
  .f-loc{color:#94a3b8;font-family:ui-monospace,monospace;font-size:11px}
  .f-vuln{font-weight:600;flex:1}
  .f-cwe{color:#64748b;font-size:11px;font-family:ui-monospace,monospace}
  .f-epss{font-size:11px;font-weight:600;color:#f59e0b;background:#f59e0b18;padding:1px 6px;border-radius:3px;white-space:nowrap}
  .f-note{font-size:11px;font-weight:600;color:#a3a3a3;background:#a3a3a318;padding:1px 6px;border-radius:3px;white-space:nowrap}
  .f-body{display:none;margin-top:12px;padding-top:12px;border-top:1px solid #1e293b;font-size:12px}
  .f.expanded .f-body{display:block}
  .f-body pre{background:#020617;padding:10px;border-radius:4px;overflow-x:auto;font-size:11px;line-height:1.5}
  .f-fix{background:#0d1f3d;border-left:3px solid #38bdf8;padding:8px 12px;margin-top:8px;border-radius:0 4px 4px 0}
  .hidden{display:none!important}
</style></head>
<body>
<header>
  <h1>agentic-security &mdash; scan report</h1>
  <div class="meta">${_esc(findings.length)} findings &middot; ${_esc(scan.filesScanned||0)} files scanned &middot; generated ${_esc(generatedAt)}</div>
</header>
<main>
  <div class="grid">
    <div class="card"><h2>By severity</h2>${sevBars}</div>
    <div class="card"><h2>STRIDE coverage</h2><table><tbody>${strideRows}</tbody></table></div>
    <div class="card"><h2>Top files</h2><table><tbody>${hotRows}</tbody></table></div>
  </div>
  <div class="filters">
    <input id="q" placeholder="Filter by file, vuln, CWE&hellip;" />
    <select id="sev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
    <select id="kind"><option value="">All scan types</option><option value="iac">IaC</option><option value="logic">Logic</option><option value="sast">SAST</option><option value="sca">SCA</option><option value="secret">Secrets</option></select>
    <button class="btn" id="toggleAll">Collapse All</button>
  </div>
  <div id="findings"></div>
</main>
<script>
const FINDINGS = ${data};
const SEV_HEX = ${JSON.stringify(SEV_HEX)};
const SECTIONS = ${JSON.stringify(SECTIONS)};
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML}

let allCollapsed = false;

function makeCard(f) {
  const hex = SEV_HEX[f.severity] || '#888';
  const div = document.createElement('div');
  div.className = 'f';
  div.dataset.sev = f.severity;
  div.dataset.file = (f.file||'').toLowerCase();
  div.dataset.vuln = (f.vuln||'').toLowerCase();
  div.dataset.cwe = (f.cwe||'').toLowerCase();
  const epssHtml = f.epssScore != null
    ? '<span class="f-epss" title="EPSS: probability of abuse in the next 30 days">EPSS ' + Math.round(f.epssScore * 100) + '%</span>'
    : '';
  div.innerHTML =
    '<div class="f-head">' +
      '<span class="sev-tag" style="background:' + hex + '22;color:' + hex + '">' + esc(f.severity) + '</span>' +
      '<span class="f-loc">' + esc(f.file) + ':' + esc(f.line) + '</span>' +
      '<span class="f-vuln">' + esc(f.vuln) + '</span>' +
      '<span class="f-cwe">' + esc(f.cwe||'') + '</span>' +
      epssHtml +
      (f._riskNote ? '<span class="f-note" title="The reachability / confidence pipeline marked this down from its rule-default severity">↓ ' + esc(f._riskNote) + '</span>' : '') +
    '</div>' +
    '<div class="f-body">' +
      (f.snippet ? '<pre>' + esc(f.snippet) + '</pre>' : '') +
      (f.masked ? '<pre style="color:#f97316">' + esc(f.masked) + ' (masked)</pre>' : '') +
      (f.fix && f.fix.description ? '<div class="f-fix"><b>Fix:</b> ' + esc(f.fix.description) + (f.fix.code ? '<pre>' + esc(f.fix.code) + '</pre>' : '') + '</div>' : '') +
    '</div>';
  div.addEventListener('click', () => div.classList.toggle('expanded'));
  return div;
}

function render() {
  const q = document.getElementById('q').value.toLowerCase();
  const sev = document.getElementById('sev').value;
  const kind = document.getElementById('kind').value;
  const root = document.getElementById('findings');
  root.innerHTML = '';
  allCollapsed = false;
  document.getElementById('toggleAll').textContent = 'Collapse All';

  for (const sec of SECTIONS) {
    if (kind && sec.kind !== kind) continue;
    const secFindings = FINDINGS.filter(f => f.kind === sec.kind);
    const visible = secFindings.filter(f =>
      (!sev || f.severity === sev) &&
      (!q || (f.file||'').toLowerCase().includes(q) || (f.vuln||'').toLowerCase().includes(q) || (f.cwe||'').toLowerCase().includes(q))
    );

    const section = document.createElement('div');
    section.className = 'section';

    const hdr = document.createElement('div');
    hdr.className = 'section-header';
    hdr.innerHTML =
      '<span style="color:' + sec.color + ';font-size:16px">' + sec.icon + '</span>' +
      '<span class="section-title" style="color:' + sec.color + '">' + esc(sec.label) + '</span>' +
      '<span class="section-count">' + visible.length + ' of ' + secFindings.length + '</span>' +
      '<span class="section-toggle">▾</span>';

    const body = document.createElement('div');
    body.className = 'section-body';

    hdr.addEventListener('click', () => {
      const collapsed = body.classList.toggle('collapsed');
      hdr.querySelector('.section-toggle').textContent = collapsed ? '▸' : '▾';
    });

    if (visible.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'section-empty';
      empty.textContent = secFindings.length === 0 ? 'No findings.' : 'All findings filtered out.';
      body.appendChild(empty);
    } else {
      for (const f of visible) body.appendChild(makeCard(f));
    }

    section.appendChild(hdr);
    section.appendChild(body);
    root.appendChild(section);
  }
}

document.getElementById('toggleAll').addEventListener('click', () => {
  allCollapsed = !allCollapsed;
  document.getElementById('toggleAll').textContent = allCollapsed ? 'Expand All' : 'Collapse All';
  document.querySelectorAll('.section-body').forEach(b => {
    b.classList.toggle('collapsed', allCollapsed);
    const toggle = b.previousElementSibling?.querySelector('.section-toggle');
    if (toggle) toggle.textContent = allCollapsed ? '▸' : '▾';
  });
});

document.getElementById('q').addEventListener('input', render);
document.getElementById('sev').addEventListener('change', render);
document.getElementById('kind').addEventListener('change', render);
render();
</script>
</body></html>`;
}

const SEV_COLOR = { critical: '\x1b[91m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[32m', info: '\x1b[36m' };
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

export function toCLI(scan, { verbose=false, color=true }={}){
  const findings = normalizeFindings(scan);
  const lines = [];
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  lines.push(c(BOLD+`Agentic Security — ${findings.length} finding(s) across ${scan.filesScanned||0} file(s)`, ''));
  lines.push('');
  for (const f of findings) {
    const sevTag = c(`[${f.severity.toUpperCase()}]`, SEV_COLOR[f.severity]||'');
    const epssTag = f.epssScore != null ? c(`  EPSS:${Math.round(f.epssScore*100)}%`, DIM) : '';
    const kevTag = f.kev ? c('  KEV', '\x1b[1;31m') : '';
    // Premortem 4R-11: surface the validator verdict so SCA findings (which
    // get tagged 'not-applicable' deliberately) don't look like they slipped
    // past validation. The dim tag is only rendered when verdict is set.
    const verdictTag = f.validator_verdict
      ? c(`  V:${f.validator_verdict}`, DIM)
      : '';
    lines.push(`${sevTag} ${c(f.cwe||'    ', DIM)}  ${f.file}:${f.line}  ${BOLD}${f.vuln}${RESET}${epssTag}${kevTag}${verdictTag}`);
    const rn = riskNote(f);
    if (rn) lines.push(`        ${c('↓ ' + rn, '\x1b[2;33m')}`);
    if (f.masked) lines.push(`        ${c('value:', DIM)} ${f.masked}`);
    if (verbose && f.fix?.description) {
      lines.push(`        ${c('fix:', DIM)} ${f.fix.description}`);
      if (f.fix.code) for (const ln of f.fix.code.split('\n').slice(0, 6)) lines.push(`           ${c(ln, DIM)}`);
    }
  }
  lines.push('');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
  lines.push(`${c('Critical:', SEV_COLOR.critical)} ${counts.critical}    ${c('High:', SEV_COLOR.high)} ${counts.high}    ${c('Medium:', SEV_COLOR.medium)} ${counts.medium}    ${c('Low:', SEV_COLOR.low)} ${counts.low}    ${c('Info:', SEV_COLOR.info)} ${counts.info}`);
  return lines.join('\n');
}

// ────────────────────────────────────────────────────────────────────────────
// PERSONA-AWARE RENDERERS (R3 + R5)
// ────────────────────────────────────────────────────────────────────────────
//
//   toShipVerdict: vibecoder default — one-screen verdict, hides taxonomy,
//                  shows up to 3 actionable items each with inline fix snippet.
//   toProTable:    pro default — table with CWE/CVSS/OWASP/MITRE columns,
//                  ranked by triage score, full taxonomy visible.
//
// Both filter by `confidenceMin` from the profile.

const CONF_DEFAULT_VIB = 0.9;
const CONF_DEFAULT_PRO = 0.3;

function _withConfidence(findings, min) {
  // confidence defaults to 1.0 when unset — engine doesn't always populate it,
  // so we never silently drop unset findings. Power users can `--firehose`.
  return findings.filter(f => (f.confidence == null ? 1.0 : f.confidence) >= min);
}

function _sevToEmoji(sev) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[sev] || '•';
}

// Per-category 0..100 score (Secrets / Permissions / Hooks / MCP / Agents).
// Each category starts at 100 and loses points by category-weighted severity.
// Used by the ship verdict to show a graded breakdown alongside the verdict.
export function categoryScores(findings) {
  const cats = {
    Secrets:     { score: 100, hits: 0 },
    Permissions: { score: 100, hits: 0 },
    Hooks:       { score: 100, hits: 0 },
    MCP:         { score: 100, hits: 0 },
    Agents:      { score: 100, hits: 0 },
  };
  const weight = { critical: 25, high: 15, medium: 6, low: 2, info: 0 };
  const classify = (f) => {
    const fam = String(f.family || '').toLowerCase();
    const vuln = String(f.vuln || '').toLowerCase();
    if (fam.includes('harness-config-secrets') || fam.includes('hardcoded') || /\bsecret\b|\bcredential\b|\bapi[-_ ]?key\b|\btoken\b/.test(vuln)) return 'Secrets';
    if (fam.includes('harness-config-permissions') || /\ballow.list\b|\bdeny.list\b|\bpermission\b|\bdangerouslySkipPermissions\b/i.test(vuln)) return 'Permissions';
    if (fam.includes('hook-command-injection') || /\bhook\b/i.test(vuln)) return 'Hooks';
    if (fam.includes('mcp') || /\bmcp\b/i.test(vuln)) return 'MCP';
    if (fam.includes('agent') || fam.includes('prompt-injection') || /\bagent\b|\bprompt[-\s]?injection\b/i.test(vuln)) return 'Agents';
    return null;
  };
  for (const f of findings) {
    const cat = classify(f);
    if (!cat) continue;
    const w = weight[(f.severity || 'low').toLowerCase()] ?? 2;
    cats[cat].score = Math.max(0, cats[cat].score - w);
    cats[cat].hits += 1;
  }
  return cats;
}

function _renderCategoryBars(cats, color) {
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  const BAR_W = 20;
  const lines = [];
  for (const [name, info] of Object.entries(cats)) {
    if (info.hits === 0 && info.score === 100) continue;          // skip uncontributed categories in compact mode
    const filled = Math.round((info.score / 100) * BAR_W);
    const empty = BAR_W - filled;
    const tier = info.score >= 90 ? SEV_COLOR.low : info.score >= 60 ? '\x1b[33m' : info.score >= 30 ? SEV_COLOR.high : SEV_COLOR.critical;
    const bar = c('█'.repeat(filled), tier) + c('░'.repeat(empty), DIM);
    lines.push(`  ${name.padEnd(14)} ${bar} ${String(info.score).padStart(3)}  ${c(`(${info.hits} finding${info.hits === 1 ? '' : 's'})`, DIM)}`);
  }
  return lines;
}

export function toShipVerdict(scan, options = {}) {
  const profile = options.profile || { confidenceMin: CONF_DEFAULT_VIB, showTaxonomy: false };
  const color = options.color !== false;
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  const findings = _withConfidence(normalizeFindings(scan), profile.confidenceMin ?? CONF_DEFAULT_VIB);
  const actionable = findings.filter(f => /critical|high/.test(f.severity));
  const advisoryCount = findings.length - actionable.length;
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
  const kevCount = findings.filter(f => f.kev === true).length;
  const confirmedCount = findings.filter(f => f.validated === true || f.confirmed === true).length;
  const cats = categoryScores(findings);

  const lines = [];
  const bar = '─────────────────────────────────────────';
  // Patch the mascot reacts to the result — APPROVE if clean, ALERT if findings.
  lines.push(actionable.length === 0 ? approveFace({ color }) : alertFace({ color }));
  lines.push(bar);
  if (actionable.length === 0) {
    lines.push(c('  ✅  Safe to deploy', SEV_COLOR.low + BOLD));
  } else {
    lines.push(c('  ❌  Not safe to deploy', SEV_COLOR.critical + BOLD));
  }
  lines.push(bar);
  lines.push(`  • ${sev.critical} critical · ${sev.high} high · ${advisoryCount} advisory`);
  // Per-category 0..100 score bars — Secrets / Permissions / Hooks / MCP / Agents.
  // Only render when at least one category has been contributed to (skip the
  // 100/100/100/100/100 baseline on pure application-code scans).
  const hasCategoryFindings = Object.values(cats).some(c => c.hits > 0);
  if (hasCategoryFindings) {
    lines.push('');
    lines.push(c('  Category breakdown', BOLD));
    for (const ln of _renderCategoryBars(cats, color)) lines.push(ln);
  }
  // KEV: surface "being exploited now" — more visceral than $-cost framing alone.
  // Only show when at least one finding is in CISA KEV (known-exploited).
  if (kevCount > 0) {
    lines.push(c(`  🔥 ${kevCount} actively exploited in the wild (CISA KEV)`, SEV_COLOR.critical + BOLD));
  }
  // CONFIRMED: surface validator-confirmed criticals as a trust signal —
  // distinguishes "tool said so" from "tool built a PoC and it ran."
  if (confirmedCount > 0) {
    lines.push(c(`  ✓  ${confirmedCount} CONFIRMED (PoC built by /triage --validate)`, '\x1b[1;32m'));
  }
  lines.push('');

  if (actionable.length) {
    // Cumulative counts so each option shows what the user is actually
    // signing up for (e.g., option 2 fixes both critical AND high).
    const nCrit = sev.critical || 0;
    const nHigh = nCrit + (sev.high || 0);
    const nMed  = nHigh + (sev.medium || 0);
    const nAll  = nMed  + (sev.low || 0);
    const fix = (n) => `${n} ${n === 1 ? 'fix' : 'fixes'}`;

    lines.push(c('  How many do you want to fix?', BOLD));
    lines.push('');
    if (nCrit > 0)        lines.push(`     1. Critical only                (${fix(nCrit)})`);
    if (nHigh > nCrit)    lines.push(`     2. Critical + High              (${fix(nHigh)})`);
    if (nMed  > nHigh)    lines.push(`     3. Critical + High + Medium     (${fix(nMed)})`);
    if (nAll  > nMed)     lines.push(`     4. All                          (${fix(nAll)})`);
    lines.push('');
    lines.push(c('  Reply with 1, 2, 3, or 4.', DIM));
    lines.push('');
    lines.push(c('  Or pick a single one:', DIM));
    lines.push(c('     /security-scan-all --firehose      see every finding', DIM));
    lines.push(c('     /security-fix --finding <id>       fix exactly one', DIM));
  } else if (advisoryCount > 0) {
    lines.push(c(`  ${advisoryCount} advisory item${advisoryCount === 1 ? '' : 's'} — run /security-scan-all --firehose to see them.`, DIM));
  }
  // Discoverability: the depth (per-finding explanation) and the shareable report
  // exist but aren't obvious from the one-screen verdict — point to them.
  if (findings.length > 0) {
    lines.push('');
    lines.push(c('  Want more detail?', BOLD));
    lines.push(c('     /triage --explain <id>             why it fired, the data-flow trace, and the fix', DIM));
    lines.push(c('     scan . --format html -o report.html   shareable browser report (charts + filters)', DIM));
  }
  // Coverage-honesty line (#5/#6): show the scan's blind spots — which
  // languages got flow analysis vs pattern-only, what was skipped, and how
  // many dangerous-looking calls had no finding. One concise line, not bloat.
  const _covMeta = scan._scanMeta;
  if (_covMeta && _covMeta.analysisTier) {
    const t = _covMeta.analysisTier;
    const pat = Object.keys(t.patternOnly || {});
    const segs = [`${_covMeta.filesScanned ?? '?'} files`];
    const ir = Object.keys(t.irTaint || {});
    if (ir.length) segs.push(`flow=[${ir.join(',')}]`);
    if (pat.length) segs.push(`pattern-only=[${pat.join(',')}]`);
    const skipped = (_covMeta.filesSkipped || 0) + (_covMeta.filesDenseSkipped || 0);
    if (skipped) segs.push(`${skipped} skipped`);
    if (_covMeta.unmodeledSinkCandidates?.count) segs.push(`${_covMeta.unmodeledSinkCandidates.count} unmodeled-sink candidate${_covMeta.unmodeledSinkCandidates.count === 1 ? '' : 's'}`);
    lines.push('');
    lines.push(c('  Coverage: ' + segs.join(' · '), DIM));
  }
  lines.push('');
  lines.push(c('  🛡  agentic-security · created by ClearCapabilities.Com', DIM));
  return lines.join('\n');
}

export function toProTable(scan, options = {}) {
  const profile = options.profile || { confidenceMin: CONF_DEFAULT_PRO, showTaxonomy: true };
  const color = options.color !== false;
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  const columns = options.columns || 'standard'; // 'standard' | 'mitre' | 'capec' | 'owasp'
  const findings = _withConfidence(normalizeFindings(scan), profile.confidenceMin ?? CONF_DEFAULT_PRO);

  // Rank by triage score (or severity rank if absent).
  findings.sort((a, b) => {
    const ea = a.triage ?? (1 - (SEV_RANK[a.severity] || 0) / 4);
    const eb = b.triage ?? (1 - (SEV_RANK[b.severity] || 0) / 4);
    return eb - ea;
  });

  const lines = [];
  lines.push(c(BOLD + `agentic-security — pro mode  ·  ${findings.length} finding(s) across ${scan.filesScanned || 0} file(s)`, ''));
  lines.push(c('created by ClearCapabilities.Com', DIM));
  lines.push('');

  // Header row depends on column profile.
  const hdr = (() => {
    if (columns === 'mitre') return ['Severity', 'File:Line', 'ATT&CK', 'Vuln', 'Conf'];
    if (columns === 'capec') return ['Severity', 'File:Line', 'CAPEC', 'Vuln', 'Conf'];
    if (columns === 'owasp') return ['Severity', 'File:Line', 'CWE', 'OWASP', 'Vuln', 'Conf'];
    return ['Severity', 'File:Line', 'CWE', 'CVSS', 'OWASP', 'Vuln', 'Conf'];
  })();
  lines.push(c(hdr.join('  '), BOLD));
  lines.push(c('─'.repeat(80), DIM));

  for (const f of findings) {
    const sev = c(_sevToEmoji(f.severity) + ' ' + (f.severity || '').toUpperCase().padEnd(8), SEV_COLOR[f.severity] || '');
    const where = `${f.file}:${f.line}`.padEnd(40);
    const cwe = (f.cwe || '—').padEnd(10);
    const cvss = (f.cvss || f.cvssV3?.score || '—').toString().padEnd(5);
    const owasp = (f.owasp || f.owaspCategory || '—').padEnd(10);
    const mitre = (f.mitreAttack || f.attckTechnique || '—').padEnd(20);
    const capec = (f.capec || '—').padEnd(10);
    const conf = (f.confidence == null ? '—' : f.confidence.toFixed(2));
    const vuln = (f.vuln || '').slice(0, 60);

    if (columns === 'mitre') lines.push(`${sev}  ${where}  ${mitre}  ${vuln}  ${conf}`);
    else if (columns === 'capec') lines.push(`${sev}  ${where}  ${capec}  ${vuln}  ${conf}`);
    else if (columns === 'owasp') lines.push(`${sev}  ${where}  ${cwe}  ${owasp}  ${vuln}  ${conf}`);
    else lines.push(`${sev}  ${where}  ${cwe}  ${cvss}  ${owasp}  ${vuln}  ${conf}`);
    const rn = riskNote(f);
    if (rn) lines.push(c('     ↓ ' + rn, '\x1b[2;33m'));
  }

  // Footer counts.
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  lines.push('');
  lines.push(
    `${c('Critical:', SEV_COLOR.critical)} ${counts.critical}  ` +
    `${c('High:', SEV_COLOR.high)} ${counts.high}  ` +
    `${c('Medium:', SEV_COLOR.medium)} ${counts.medium}  ` +
    `${c('Low:', SEV_COLOR.low)} ${counts.low}  ` +
    `${c('Info:', SEV_COLOR.info)} ${counts.info}`
  );
  lines.push('');
  lines.push(c('Machine-readable output written to .agentic-security/findings.{sarif,json,csv}', DIM));
  return lines.join('\n');
}

// Persona dispatcher. Picks the renderer based on the profile.
export function toCLIByProfile(scan, options = {}) {
  const profile = options.profile || {};
  if (profile.profile === 'pro') return toProTable(scan, options);
  return toShipVerdict(scan, options);
}

export function toSummary(scan, { color=true }={}){
  const findings = normalizeFindings(scan);
  const lines = [];
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;

  lines.push(c(BOLD + `Agentic Security — ${findings.length} finding(s) across ${scan.filesScanned||0} file(s)`, ''));
  lines.push('');
  lines.push(
    `  ${c('Critical', SEV_COLOR.critical)}  ${String(counts.critical).padEnd(4)}` +
    `  ${c('High', SEV_COLOR.high)}  ${String(counts.high).padEnd(4)}` +
    `  ${c('Medium', SEV_COLOR.medium)}  ${String(counts.medium).padEnd(4)}` +
    `  ${c('Low', SEV_COLOR.low)}  ${String(counts.low).padEnd(4)}` +
    `  ${c('Info', SEV_COLOR.info)}  ${counts.info}`
  );
  lines.push('');

  // Group findings by severity then vuln type, show top 3 examples per group
  const SEVERITIES = ['critical', 'high', 'medium', 'low'];
  for (const sev of SEVERITIES) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (!sevFindings.length) continue;

    const label = sev.charAt(0).toUpperCase() + sev.slice(1);
    lines.push(c(`${label} (${sevFindings.length})`, SEV_COLOR[sev]));

    // Group by vuln type
    const byVuln = new Map();
    for (const f of sevFindings) {
      if (!byVuln.has(f.vuln)) byVuln.set(f.vuln, []);
      byVuln.get(f.vuln).push(f);
    }

    const vulnEntries = [...byVuln.entries()].sort((a, b) => b[1].length - a[1].length);
    const shown = vulnEntries.slice(0, 6);
    const hiddenTypes = vulnEntries.length - shown.length;

    for (let i = 0; i < shown.length; i++) {
      const [vuln, instances] = shown[i];
      const isLast = i === shown.length - 1 && hiddenTypes === 0;
      const prefix = isLast ? '└──' : '├──';
      const examples = instances.slice(0, 2).map(f => `${f.file}:${f.line}`).join(', ');
      const more = instances.length > 2 ? c(` +${instances.length - 2} more`, DIM) : '';
      const epssScores = instances.map(f => f.epssScore).filter(s => s != null);
      const epssTag = epssScores.length ? c(`  EPSS:${Math.round(Math.max(...epssScores)*100)}%`, DIM) : '';
      lines.push(`  ${prefix} ${c(`${vuln} ×${instances.length}`, BOLD)}  ${c(examples, DIM)}${more}${epssTag}`);
    }
    if (hiddenTypes > 0) {
      lines.push(`  └── ${c(`…and ${hiddenTypes} more vulnerability type${hiddenTypes > 1 ? 's' : ''}`, DIM)}`);
    }
    lines.push('');
  }

  // Top files by finding count
  const byFile = new Map();
  for (const f of findings.filter(x => x.severity !== 'info')) {
    byFile.set(f.file, (byFile.get(f.file) || 0) + 1);
  }
  const topFiles = [...byFile.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (topFiles.length) {
    lines.push(c('Top files', BOLD));
    for (const [file, count] of topFiles) {
      lines.push(`  ${c(String(count).padStart(3), SEV_COLOR.high)}  ${file}`);
    }
    lines.push('');
  }

  lines.push(c(`Run /security-report to generate a full interactive HTML report.`, DIM));
  return lines.join('\n');
}

export function exitCodeFor(scan){
  const findings = normalizeFindings(scan);
  if (findings.some(f=>f.severity==='critical')) return 3;
  if (findings.some(f=>f.severity==='high')) return 2;
  if (findings.some(f=>f.severity==='medium' || f.severity==='low')) return 1;
  return 0;
}
