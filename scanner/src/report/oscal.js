// OSCAL export — NIST's Open Security Controls Assessment Language.
// Model reference: https://pages.nist.gov/OSCAL-Reference/models/
//
// ── WHICH MODEL, AND WHY ─────────────────────────────────────────────────────
//
// OSCAL has seven models. Exactly one of them describes "something examined a
// system and reports what it found": `assessment-results`. A catalog and a
// profile describe control DEFINITIONS; an SSP describes a system DESIGN; a
// POA&M records PLANNED remediation with owners and due dates. A scanner is not
// entitled to author any of those — it has no owners, no dates, and no
// authority over a control catalog. So both exporters here emit
// `assessment-results`, and the only difference between them is what the
// single `result` says it REVIEWED.
//
// ── THE HONESTY PROBLEM OSCAL FORCES ─────────────────────────────────────────
//
// An OSCAL `finding` is a statement ABOUT A CONTROL. It requires a `target`
// carrying a `target-id` and a `status.state` that is binary: satisfied or
// not-satisfied. There is no "unknown", no "not applicable", and no "we did not
// look". That constraint is the useful part of the format, and it decides the
// shape of everything below:
//
//   1. A RAW SCAN EMITS NO `findings`. A SQL-injection hit is not an opinion
//      about any control, because no catalog is in scope. It becomes an
//      `observation` (what the tool saw) and a `risk` (what it would mean).
//      Inventing control targets for CWEs would be publishing a mapping nobody
//      wrote and no assessor agreed to.
//
//   2. A COMPLIANCE EVALUATION EMITS FINDINGS ONLY FOR CONTROLS THE ENGINE
//      ACTUALLY DECIDED. Both upstream assessors distinguish "decided" from
//      "not assessed" — `auditor-walkthrough.js` returns present / partial /
//      manual, and `privacy-framework.js` returns satisfied / gap / engine-gap /
//      manual. Only the decided ones become findings. A `manual` or
//      `engine-gap` control becomes an observation with method EXAMINE and an
//      explicit remark that a human must assess it. Calling it satisfied would
//      be a false compliance claim; calling it not-satisfied would be a false
//      failure. OSCAL has no third state, so it is not a finding at all — and
//      the raw upstream status rides along as a prop so the distinction that
//      OSCAL cannot express is still in the document.
//
// ── DETERMINISM ──────────────────────────────────────────────────────────────
//
// Every uuid is minted through `_uuid`, which mirrors posture/sbom.js: a
// content-derived, v4-shaped digest under `--deterministic`, a real random uuid
// otherwise. Cross-references (finding → related-observations → observation) are
// computed once and reused, so they hold in both modes. `format-determinism`
// covers this format; a `crypto.randomUUID()` added anywhere below without the
// deterministic branch fails that gate.

import crypto from 'node:crypto';
import { isDeterministic, SCANNER_VERSION } from '../posture/deterministic.js';
import { normalizeFindings, TOOL_CAVEATS } from './index.js';
import { EVIDENCE_GRADE_DISCLAIMER } from '../posture/evidence-grade-wording.js';

// The OSCAL release these documents declare conformance to. Bump deliberately:
// `oscal-version` is a claim a validator checks the rest of the document
// against, not a decoration.
const OSCAL_VERSION = '1.1.2';

// Every extension this file adds lives under one namespace, so a consumer can
// drop everything it does not understand with a single filter instead of
// guessing which bare prop names are ours.
export const OSCAL_NS = 'https://github.com/Clear-Capabilities/agentic-security/ns/oscal';

const TOOL_URI = 'https://github.com/Clear-Capabilities/agentic-security';

// ── primitives ───────────────────────────────────────────────────────────────

function _stableUuidFrom(seed) {
  const h = crypto.createHash('sha256').update(String(seed)).digest('hex');
  // Shaped as a v4 uuid — version and variant nibbles set — because OSCAL's
  // `uuid` datatype is validated, and a bare 32-char digest is rejected.
  return [
    h.slice(0, 8),
    h.slice(8, 12),
    `4${h.slice(13, 16)}`,
    `${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}`,
    h.slice(20, 32),
  ].join('-');
}

function _uuid(seed) {
  return isDeterministic() ? _stableUuidFrom(seed) : crypto.randomUUID();
}

/**
 * OSCAL's `token` datatype is an NCName: it must start with a letter or `_` and
 * may then contain only letters, digits, `.`, `-` and `_`.
 *
 * This matters more than it looks. Real control identifiers routinely are not
 * tokens — the CCPA catalog shipped with this engine uses ids like `§1798.100`,
 * and GDPR uses `Art. 32(1)(a)`. Emitting those raw as a `control-id` or a
 * `target-id` produces a document that fails validation at the first control,
 * which is the failure mode of every "we support OSCAL" claim that was never
 * run through a validator. The original id is never lost: it is carried beside
 * the token as a `source-control-id` prop, and as the human-readable title.
 */
export function oscalToken(s) {
  const raw = String(s == null ? '' : s);
  const cleaned = raw.replace(/[^\p{L}\p{N}._-]/gu, '-');
  return /^[\p{L}_]/u.test(cleaned) ? cleaned : `_${cleaned}`;
}

function _when(meta) {
  // `--deterministic` pins meta.startedAt to the epoch; ordinary runs carry the
  // real scan start. Either way this is the scan's clock, never a fresh read of
  // the wall clock at emit time, which would differ between two emits of one
  // scan and make the artifact unattestable.
  return (meta && meta.startedAt) || new Date().toISOString();
}

function _prop(name, value) {
  return { ns: OSCAL_NS, name, value: String(value) };
}

function _metadata(title, meta) {
  return {
    title,
    'last-modified': _when(meta),
    // The DOCUMENT version. Pinned to the engine version so re-emitting the
    // same scan with the same engine yields the same document — a wall-clock or
    // counter-based version would break determinism for no benefit.
    version: SCANNER_VERSION,
    'oscal-version': OSCAL_VERSION,
    ...(meta && meta.scanId ? { props: [_prop('scan-id', meta.scanId)] } : {}),
  };
}

/**
 * The tool, as an OSCAL assessment asset. This is the structural equivalent of
 * SARIF's `tool.driver`: it gives every observation an `origin` to point at, so
 * a reader can tell a machine observation from a human one without reading
 * prose.
 */
function _toolComponent() {
  return {
    uuid: _uuid('agentic-security:assessment-asset:scanner'),
    type: 'software',
    title: 'agentic-security',
    description:
      'Static analysis, supply-chain, secrets and LLM-security scanner. Produced every observation in this document by automated examination of source code; no human assessor reviewed these results.',
    props: [_prop('version', SCANNER_VERSION), _prop('information-uri', TOOL_URI)],
    status: { state: 'operational' },
  };
}

function _toolOrigin(toolUuid) {
  return [{ actors: [{ type: 'tool', 'actor-uuid': toolUuid }] }];
}

/**
 * `assessment-assets` hangs off the RESULT's local-definitions, not the
 * document's — `assessment-results/local-definitions` carries
 * objectives-and-methods and activities, and nothing else. It was written at
 * document level first; getting it wrong costs nothing at emit time and
 * everything at validation time, which is the whole reason a format claim has
 * to be checked rather than asserted.
 *
 * `assessment-platforms` is required inside it and must be non-empty. The
 * platform is what RAN the assessment; the component is the software it ran.
 * Here they are the same program described two ways, and `uses-components`
 * links them so a reader is not left to infer it.
 */
function _assessmentAssets(tool) {
  return {
    components: [tool],
    'assessment-platforms': [{
      uuid: _uuid('agentic-security:assessment-platform'),
      title: 'agentic-security command-line scanner',
      'uses-components': [{ 'component-uuid': tool.uuid }],
    }],
  };
}

/**
 * The caveats, as OSCAL back-matter. SARIF carries these as run notifications;
 * OSCAL has no notification concept, and `back-matter.resources` is the model's
 * general-purpose "documents this assessment depends on" slot. Referenced from
 * the result's `links` so they are reachable from the result rather than
 * stranded at the bottom of the file.
 */
function _caveatResources() {
  return TOOL_CAVEATS.map(c => ({
    uuid: _uuid(`caveat:${c.id}`),
    title: c.shortDescription,
    description: c.fullDescription,
    props: [_prop('caveat-id', c.id)],
  }));
}

// ── scan → assessment-results ────────────────────────────────────────────────

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function _findingProps(f) {
  const props = [];
  if (f.severity) props.push(_prop('severity', f.severity));
  if (f.cwe) props.push(_prop('cwe', f.cwe));
  if (f.family) props.push(_prop('family', f.family));
  if (f.stride) props.push(_prop('stride', f.stride));
  if (f.file) props.push(_prop('file', String(f.file).replace(/\\/g, '/')));
  if (Number.isInteger(f.line)) props.push(_prop('line', f.line));
  if (f.stableId) props.push(_prop('stable-id', f.stableId));
  // Tier labels, not the raw scores. The numbers are ordinal (see TOOL_CAVEATS)
  // and a compliance reader is precisely the reader most likely to treat a
  // decimal in a NIST-shaped document as a probability.
  if (f.confidenceTier) props.push(_prop('confidence-tier', f.confidenceTier));
  if (f.exploitabilityTier) props.push(_prop('exploitability-tier', f.exploitabilityTier));
  if (f.evidence && f.evidence.proofTier) props.push(_prop('proof-tier', f.evidence.proofTier));
  if (f.unreachable) props.push(_prop('reachability', 'demoted-unreachable'));
  if (f.validator_verdict) props.push(_prop('validator-verdict', f.validator_verdict));
  return props;
}

function _describe(f) {
  return f.description || (f.fix && f.fix.description) || f.vuln || 'Security finding';
}

/**
 * A scan, as an OSCAL assessment-results document.
 *
 * Emits observations (what was seen) and risks (what it would mean), and NO
 * findings — see the header. `reviewed-controls` is present because the model
 * requires it, and says plainly that no catalog was in scope rather than
 * claiming `include-all`, which would assert this scan reviewed every control
 * of an unnamed catalog.
 */
export function toOSCAL(scan, meta = {}) {
  const findings = normalizeFindings(scan);
  const when = _when(meta);
  const tool = _toolComponent();
  const caveats = _caveatResources();

  const observations = [];
  const risks = [];

  findings.forEach((f, i) => {
    const key = f.stableId || f.id || `${f.file}:${f.line}:${f.vuln}:${i}`;
    const obsUuid = _uuid(`observation:${key}`);
    const file = f.file ? String(f.file).replace(/\\/g, '/') : null;
    const where = file ? `${file}:${Number.isInteger(f.line) ? f.line : '?'}` : 'location not recorded';

    observations.push({
      uuid: obsUuid,
      title: f.vuln || 'Security finding',
      description: `${_describe(f)} (observed at ${where})`,
      // TEST, not EXAMINE: this is automated analysis of the artifact, which is
      // what OSCAL's TEST method means. EXAMINE is reserved below for the
      // controls a human still has to look at.
      methods: ['TEST'],
      types: ['finding'],
      origins: _toolOrigin(tool.uuid),
      ...(file
        ? {
          'relevant-evidence': [{
            href: encodeURI(file),
            description: `Source location reported by the scanner: ${where}.`,
          }],
        }
        : {}),
      collected: when,
      props: _findingProps(f),
    });

    const remediation = typeof f.remediation === 'string' ? f.remediation.trim() : '';
    risks.push({
      uuid: _uuid(`risk:${key}`),
      title: f.vuln || 'Security finding',
      description: _describe(f),
      // `statement` is the impact statement. It deliberately does not assert
      // exploitability: the engine reports the presence of a weakness pattern,
      // and only an execution-proven finding (proof-tier prop) says more.
      statement:
        `A ${f.cwe || 'weakness'} pattern was detected at ${where}. `
        + 'This document records the presence of the pattern and its severity ranking. '
        + 'It does not assert that the weakness is reachable or exploitable in deployment '
        + 'unless the observation carries a proof-tier property stating otherwise.',
      props: _findingProps(f),
      // Every scanner finding is by definition unaddressed at emit time — the
      // scan just found it. A closed risk would have to come from remediation
      // state this document does not have.
      status: 'open',
      'related-observations': [{ 'observation-uuid': obsUuid }],
      ...(remediation
        ? {
          remediations: [{
            uuid: _uuid(`response:${key}`),
            // `recommendation`, not `planned`: nobody has committed to this.
            lifecycle: 'recommendation',
            title: 'Recommended remediation',
            description: remediation,
          }],
        }
        : {}),
    });
  });

  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

  const resultUuid = _uuid(`result:scan:${meta.scanId || ''}:${findings.length}`);
  return {
    uuid: _uuid(`assessment-results:scan:${meta.scanId || ''}:${findings.length}`),
    metadata: _metadata('Automated security assessment results', meta),
    // `import-ap` is REQUIRED by the model and there is no separate OSCAL
    // assessment plan — this scan was not run against one. A same-document
    // fragment reference is a valid uri-reference and says exactly that, rather
    // than pointing at a plan that does not exist.
    'import-ap': {
      href: `#${resultUuid}`,
      remarks:
        'No OSCAL assessment plan governs this run. The scan was executed directly by the tool named in '
        + 'local-definitions.assessment-assets; this reference is a self-reference recorded because the '
        + 'OSCAL assessment-results model requires import-ap.',
    },
    results: [{
      uuid: resultUuid,
      'local-definitions': { 'assessment-assets': _assessmentAssets(tool) },
      title: 'Automated source-code security scan',
      description:
        `Automated scan of ${scan && scan.filesScanned ? scan.filesScanned : 0} file(s) producing `
        + `${findings.length} observation(s). No control catalog was assessed — see reviewed-controls.`,
      start: when,
      props: [
        _prop('files-scanned', (scan && scan.filesScanned) || 0),
        _prop('observation-count', findings.length),
        ...SEVERITY_ORDER.filter(s => bySeverity[s]).map(s => _prop(`count-${s}`, bySeverity[s])),
      ],
      links: caveats.map(c => ({ href: `#${c.uuid}`, rel: 'reference' })),
      'reviewed-controls': {
        description:
          'No control catalog was in scope. This result reports weaknesses found in source code, not the '
          + 'satisfaction of controls; consequently it contains observations and risks but no findings, '
          + 'because an OSCAL finding is a statement about a control. For a control-level document, run '
          + 'the compliance exporter against a named framework.',
        'control-selections': [{
          description: 'No controls selected: a source-code scan does not review a control catalog.',
        }],
      },
      observations,
      risks,
      remarks: TOOL_CAVEATS.map(c => `${c.id}: ${c.shortDescription}`).join(' | '),
    }],
    'back-matter': { resources: caveats },
  };
}

// ── compliance → assessment-results ──────────────────────────────────────────

/**
 * The normalized row every compliance adapter produces. One per control.
 *
 * `decision` is the only field OSCAL cares about and the only one with a
 * closed set:
 *   'satisfied'    → a finding, target status satisfied
 *   'not-satisfied'→ a finding, target status not-satisfied, plus an open risk
 *   'unassessed'   → NO finding. An observation with method EXAMINE, and the
 *                    upstream status carried in `statusLabel` so the reason the
 *                    engine could not decide survives into the document.
 */
function _decisionOf(row) {
  return row.decision === 'satisfied' || row.decision === 'not-satisfied' ? row.decision : 'unassessed';
}

/**
 * How each upstream status maps onto OSCAL's binary finding state. Written out
 * exhaustively and on purpose.
 *
 * The first version of this adapter mapped `present` to satisfied, `partial` to
 * not-satisfied and EVERYTHING ELSE to unassessed. `evaluateFramework` also
 * returns `absent` — signals exist and not one of them cleared, the strongest
 * failure the evaluator can express — and the catch-all quietly relabelled it
 * "requires human judgement", deleting real control failures from the document
 * and attaching a remark that was simply false. It was caught by running the
 * exporter against a bundled framework and reading the output, not by review.
 *
 * So: no catch-all. An unrecognised status is still reported (dropping a
 * control would be worse) but it is reported AS unrecognised, with its raw
 * value, so the next status added upstream shows up as a visible gap here
 * instead of a silent misclassification.
 */
const EVALUATION_DECISION = Object.freeze({
  present: 'satisfied',
  partial: 'not-satisfied',
  absent: 'not-satisfied',
  manual: 'unassessed',
});

/**
 * Adapter for `auditor-walkthrough.js#evaluateFramework`, whose rows are
 * `{ control, status, observations[] }`.
 */
export function complianceRowsFromEvaluation(evaluation) {
  return (evaluation || []).map(r => {
    const status = r.status || 'manual';
    return {
      id: (r.control && r.control.id) || 'unknown',
      title: (r.control && r.control.summary) || '',
      decision: EVALUATION_DECISION[status] || 'unassessed',
      statusLabel: status,
      known: Object.prototype.hasOwnProperty.call(EVALUATION_DECISION, status),
      observations: (r.observations || []).map(o => (typeof o === 'string' ? o : (o && (o.text || o.summary)) || JSON.stringify(o))),
      props: [
        ...(r.control && r.control.codeTestable ? [_prop('code-testable', r.control.codeTestable)] : []),
        ...(r.evidence && r.evidence.tier ? [_prop('evidence-tier', r.evidence.tier)] : []),
        ...(r.partiallyEvidenced ? [_prop('partially-evidenced', 'true')] : []),
      ],
    };
  });
}

/**
 * Adapter for `privacy-framework.js#assessPrivacyFramework`, whose controls are
 * bucketed satisfied | gap | engine-gap | manual.
 *
 * `engine-gap` is the interesting one: NIST rates the control code-testable and
 * this engine has no check for it. That is NOT a control failure and it is NOT
 * a human-judgement control — it is a hole in the tool. OSCAL cannot express
 * that, so it becomes an unassessed observation whose `statusLabel` prop says
 * `engine-gap`, and the remark names the tool as the reason. Folding it into
 * not-satisfied would blame the system for the scanner's coverage.
 */
const PRIVACY_DECISION = Object.freeze({
  satisfied: 'satisfied',
  gap: 'not-satisfied',
  manual: 'unassessed',
  'engine-gap': 'unassessed',
});

export function complianceRowsFromPrivacy(assessment) {
  const remediationFor = id =>
    ((assessment.findings || []).find(f => f.id === `privacy-framework:${id}`) || {}).remediation || '';
  return (assessment.controls || []).map(c => ({
    id: c.id,
    title: c.summary || '',
    decision: PRIVACY_DECISION[c.bucket] || 'unassessed',
    statusLabel: c.bucket,
    known: Object.prototype.hasOwnProperty.call(PRIVACY_DECISION, c.bucket),
    observations: [],
    remediation: remediationFor(c.id),
    props: [],
  }));
}

const UNASSESSED_REMARK = {
  unrecognised:
    'Not assessed: the evaluator reported a status this exporter does not recognise, so no satisfied/'
    + 'not-satisfied claim is made. The raw status is on the assessment-status property. This is a defect '
    + 'in the exporter, not a statement about the control.',
  manual:
    'Not assessed by automated means: this control requires human judgement and has no code-testable mapping. '
    + 'Absence of a finding is not evidence of compliance.',
  'engine-gap':
    'Not assessed by this tool: the control is rated code-testable by its publisher, but this engine implements '
    + 'no check for it. This is a coverage gap in the scanner, NOT a defect in the assessed system.',
};

/**
 * A control assessment, as an OSCAL assessment-results document.
 *
 * @param framework `{ id, name, publisher, url, license, controls? }` — the
 *        catalog metadata as loaded from the framework JSON.
 * @param rows normalized control rows from one of the adapters above.
 */
export function toOSCALCompliance(framework, rows, meta = {}) {
  const when = _when(meta);
  const tool = _toolComponent();
  const caveats = _caveatResources();
  const fw = framework || {};
  const list = rows || [];

  const frameworkResource = {
    uuid: _uuid(`framework:${fw.id || fw.name || 'unknown'}`),
    title: fw.name || String(fw.id || 'Control framework'),
    description:
      `Control set assessed by this document.${fw.publisher ? ` Published by ${fw.publisher}.` : ''}`
      + `${fw.license ? ` License: ${fw.license}.` : ''}`,
    props: [
      ...(fw.id ? [_prop('framework-id', fw.id)] : []),
      ...(fw.controlsDigest ? [_prop('controls-digest', fw.controlsDigest)] : []),
    ],
    ...(fw.url ? { rlinks: [{ href: fw.url }] } : {}),
  };

  const observations = [];
  const findings = [];
  const risks = [];

  list.forEach((row, i) => {
    const decision = _decisionOf(row);
    const token = oscalToken(row.id);
    const obsUuid = _uuid(`compliance-observation:${fw.id}:${row.id}:${i}`);
    const detail = (row.observations || []).filter(Boolean).join(' ');

    observations.push({
      uuid: obsUuid,
      title: `${row.id} — ${row.title}`.trim(),
      description: detail
        || (decision === 'unassessed'
          ? `Control ${row.id} was not assessed by automated means.`
          : `Control ${row.id} was assessed from scanner evidence.`),
      // EXAMINE for what a human still owns, TEST for what the engine decided.
      // This is the field an auditor filters on to build their own worklist.
      methods: decision === 'unassessed' ? ['EXAMINE'] : ['TEST'],
      types: ['control-objective'],
      origins: _toolOrigin(tool.uuid),
      collected: when,
      props: [
        _prop('source-control-id', row.id),
        _prop('assessment-status', row.statusLabel || decision),
        ...(row.props || []),
      ],
      ...(decision === 'unassessed'
        ? { remarks: row.known === false
          ? UNASSESSED_REMARK.unrecognised
          : (UNASSESSED_REMARK[row.statusLabel] || UNASSESSED_REMARK.manual) }
        : {}),
    });

    if (decision === 'unassessed') return;

    const findingUuid = _uuid(`compliance-finding:${fw.id}:${row.id}:${i}`);
    const riskUuid = decision === 'not-satisfied' ? _uuid(`compliance-risk:${fw.id}:${row.id}:${i}`) : null;

    findings.push({
      uuid: findingUuid,
      title: `${row.id} — ${row.title}`.trim(),
      description: detail || `Automated assessment of control ${row.id}.`,
      props: [_prop('source-control-id', row.id), _prop('assessment-status', row.statusLabel || decision)],
      origins: _toolOrigin(tool.uuid),
      target: {
        // `objective-id`, not `statement-id`: these frameworks are control
        // objectives, not statements of an implemented SSP component, and this
        // document does not reference an SSP.
        type: 'objective-id',
        'target-id': token,
        title: row.title || row.id,
        status: {
          state: decision,
          reason: decision === 'satisfied' ? 'pass' : 'fail',
        },
      },
      'related-observations': [{ 'observation-uuid': obsUuid }],
      ...(riskUuid ? { 'related-risks': [{ 'risk-uuid': riskUuid }] } : {}),
      remarks:
        decision === 'satisfied'
          ? 'Satisfied means the automated signals mapped to this control cleared. It is scanner evidence '
            + 'toward the control, not an attestation that the control is implemented and operating.'
          : 'Not satisfied: at least one automated signal mapped to this control did not clear.',
    });

    if (riskUuid) {
      const remediation = typeof row.remediation === 'string' ? row.remediation.trim() : '';
      risks.push({
        uuid: riskUuid,
        title: `Control not satisfied: ${row.id}`,
        description: row.title || `Control ${row.id}`,
        statement: detail
          || `Automated signals mapped to control ${row.id} did not clear at assessment time.`,
        props: [_prop('source-control-id', row.id)],
        status: 'open',
        'related-observations': [{ 'observation-uuid': obsUuid }],
        ...(remediation
          ? {
            remediations: [{
              uuid: _uuid(`compliance-response:${fw.id}:${row.id}:${i}`),
              lifecycle: 'recommendation',
              title: 'Recommended remediation',
              description: remediation,
            }],
          }
          : {}),
      });
    }
  });

  const counts = { satisfied: 0, 'not-satisfied': 0, unassessed: 0 };
  for (const row of list) counts[_decisionOf(row)]++;

  const resultUuid = _uuid(`compliance-result:${fw.id}:${list.length}`);
  return {
    uuid: _uuid(`compliance-assessment-results:${fw.id}:${list.length}`),
    metadata: _metadata(`${fw.name || fw.id || 'Control framework'} — automated control assessment`, meta),
    'import-ap': {
      href: `#${resultUuid}`,
      remarks:
        'No OSCAL assessment plan governs this assessment. Controls were evaluated directly from scanner '
        + 'evidence by the tool named in local-definitions.assessment-assets; this reference is a '
        + 'self-reference recorded because the OSCAL assessment-results model requires import-ap.',
    },
    results: [{
      uuid: resultUuid,
      'local-definitions': { 'assessment-assets': _assessmentAssets(tool) },
      title: `${fw.name || fw.id || 'Control framework'} assessment`,
      description:
        `${list.length} control(s) reviewed: ${counts.satisfied} satisfied, ${counts['not-satisfied']} not `
        + `satisfied, ${counts.unassessed} NOT ASSESSED. Unassessed controls carry no finding — an OSCAL `
        + 'finding requires a binary satisfied/not-satisfied state, and asserting either for a control '
        + 'nobody checked would be false. They appear as observations with method EXAMINE.',
      start: when,
      props: [
        _prop('controls-reviewed', list.length),
        _prop('count-satisfied', counts.satisfied),
        _prop('count-not-satisfied', counts['not-satisfied']),
        _prop('count-unassessed', counts.unassessed),
        ...(fw.id ? [_prop('framework-id', fw.id)] : []),
      ],
      links: [
        { href: `#${frameworkResource.uuid}`, rel: 'source' },
        ...caveats.map(c => ({ href: `#${c.uuid}`, rel: 'reference' })),
      ],
      'reviewed-controls': {
        description: `${fw.name || fw.id || 'Control framework'}${fw.publisher ? ` (${fw.publisher})` : ''}.`
          + ' Control identifiers are OSCAL tokens derived from the publisher\'s identifiers; the original'
          + ' identifier is carried on each observation and finding as a source-control-id property.',
        'control-selections': [{
          description: 'Every control in the framework as loaded by the engine.',
          'include-controls': list.map(r => ({ 'control-id': oscalToken(r.id) })),
        }],
      },
      observations,
      ...(findings.length ? { findings } : {}),
      ...(risks.length ? { risks } : {}),
      // FR-507: names all three assurance tiers explicitly, not just "not
      // certified" — see evidence-grade-wording.js for why that distinction
      // matters (a reader who has never heard "attestation" used correctly
      // has no way to know a real one is a different, valid artifact they
      // might separately need).
      remarks:
        `${EVIDENCE_GRADE_DISCLAIMER} No licensed assessor reviewed this document. `
        + TOOL_CAVEATS.map(c => `${c.id}: ${c.shortDescription}`).join(' | '),
    }],
    'back-matter': { resources: [frameworkResource, ...caveats] },
  };
}
