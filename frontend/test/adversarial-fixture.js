// adversarial-fixture.js — Milestone 3, sub-project XSS.
//
// A hand-built DataFlowGraph v1-shaped object with HOSTILE VALUES in every
// user-influenceable string field a view actually renders (node label/
// aliases, dataElement name, evidence claim/reason, flow governance text).
// Test-only, throwaway data — never mixed with the real, committed
// flagship-graph.json fixture. Not run through the backend's own
// validateGraph() (this file never leaves the frontend, and the whole point
// is exercising rendering code with values a real backend scan COULD
// produce from a hostile repository — see docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md's
// T1 entry).
//
// Categories covered, per T1's own named list:
//   - a raw <script> tag
//   - an SVG-specific payload (<svg onload=...>) — architecture-view.js
//     renders into a real <svg> tree via svgEl(), so this is a genuinely
//     relevant category this file's own architecture makes worth testing
//     specifically, not just generic HTML
//   - an HTML img/onerror-style event-handler payload
//   - a javascript: URL-shaped string — included as a regression trip-wire
//     even though NO current view renders any value as an href/src
//     attribute (confirmed by grep across src/views, src/components,
//     src/app.js this session) — this category is honestly testing an
//     ABSENCE today, not an active defense; disclosed here, not silently
//     treated as "this proves something is protected"
//   - control characters (a null byte + bell + backspace, via \x escapes —
//     never a literal raw control byte in this source file itself, which
//     would be fragile/invisible in a diff) embedded in an identifier-
//     shaped string
//   - an extremely long identifier (10,000 chars) — see
//     docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-xss-plan.md's
//     own disclosed decision on why this is NOT truncated by this
//     increment (el()'s escaping already makes it inert as markup; an
//     unbounded label is a display/DoS-adjacent UX concern, not itself an
//     XSS vector, and truncation is deferred)

export const SCRIPT_TAG = '<script>window.__xss_fired = true;</script>';
export const SVG_PAYLOAD = '<svg onload="window.__xss_fired = true"><animate onbegin="window.__xss_fired = true"/></svg>';
export const IMG_ONERROR = '<img src=x onerror="window.__xss_fired = true">';
export const JS_URL = 'javascript:window.__xss_fired = true';
export const CONTROL_CHARS = 'evil' + '\x00' + 'field' + '\x07' + 'name' + '\x08';
export const LONG_IDENTIFIER = 'A'.repeat(10000);

export const ADVERSARIAL_GRAPH = Object.freeze({
  schemaVersion: '1.0.0',
  graphId: 'dfg:adversarial-test:0000000000000000000000000000000000000000:test',
  generatedAt: '2026-09-01T00:00:00.000Z',
  scope: { source: 'fixture', repository: SCRIPT_TAG, commit: '0'.repeat(40), environment: 'production' },
  scanHealth: { status: 'complete', reason: 'adversarial-test-fixture' },
  taxonomy: { version: '1.0.0', source: 'test' },
  nodes: [
    {
      id: 'node:source:evil1',
      kind: 'source',
      subtype: 'web-app',
      label: SVG_PAYLOAD,
      aliases: [IMG_ONERROR, LONG_IDENTIFIER],
      location: null,
      system: { application: CONTROL_CHARS, environment: 'production' },
      destination: null,
      externality: { value: 'internal', evidenceRefs: [] },
      lifecycleStages: ['collection'],
      governanceRefs: {},
      dataElementIds: ['data:evil1'],
      evidenceRefs: ['evidence:evil1'],
      confidence: { score: 1, tier: 'high' },
      coverageStatus: 'modeled',
    },
    {
      id: 'node:store:evil2',
      kind: 'store',
      subtype: 'database',
      label: JS_URL,
      aliases: [SCRIPT_TAG],
      location: null,
      system: { application: 'adversarial-test', environment: 'production' },
      destination: null,
      externality: { value: 'internal', evidenceRefs: [] },
      lifecycleStages: ['storage'],
      governanceRefs: {},
      dataElementIds: ['data:evil1'],
      evidenceRefs: [],
      confidence: { score: 1, tier: 'high' },
      coverageStatus: 'modeled',
    },
  ],
  edges: [
    {
      id: 'edge:evil1',
      from: 'node:source:evil1',
      to: 'node:store:evil2',
      relationship: 'data_flow',
      fieldMappings: [{ fromPath: SCRIPT_TAG, toPath: IMG_ONERROR, dataElementIds: ['data:evil1'], mappingType: 'identity', transformationIds: [] }],
      protocol: { name: 'in-process', destinationResolution: 'literal' },
      boundaryCrossings: [SVG_PAYLOAD],
      provenance: 'code',
      protection: {
        transit: { verdict: 'not_assessed', evidenceGrade: 'none' },
        atRest: { verdict: 'not_assessed', evidenceGrade: 'none' },
        handling: { verdict: 'not_assessed', evidenceGrade: 'none' },
      },
      evidenceRefs: ['evidence:evil1'],
      coverageStatus: 'modeled',
    },
  ],
  dataElements: [
    {
      id: 'data:evil1',
      name: CONTROL_CHARS,
      aliases: [LONG_IDENTIFIER],
      declaredType: null,
      dataClasses: ['PII'],
      aiContexts: [],
      sourceLocations: [],
      dataSubjectCategory: null,
      classificationEvidence: [],
      manualOverride: false,
    },
  ],
  transformations: [],
  flows: [
    {
      id: 'flow:evil1',
      dataElementIds: ['data:evil1'],
      source: 'node:source:evil1',
      sink: 'node:store:evil2',
      edgeIds: ['edge:evil1'],
      transformationIds: [],
      alternatePathCount: 0,
      policyVerdict: 'not_evaluated',
      protectionSummary: 'not_assessed',
      evidenceRefs: ['evidence:evil1'],
      confidence: { score: 1, tier: 'high' },
      coverageStatus: 'modeled',
      findingRefs: [],
      governanceRefs: {
        purpose: SCRIPT_TAG,
        lawfulBasis: SVG_PAYLOAD,
        recipient: IMG_ONERROR,
        transfer: JS_URL,
        retention: CONTROL_CHARS,
        deletion: LONG_IDENTIFIER,
      },
      limitations: [SCRIPT_TAG],
    },
  ],
  controls: [],
  policies: [],
  evidence: [
    {
      id: 'evidence:evil1',
      claim: SCRIPT_TAG,
      evidenceType: 'code',
      location: { file: SVG_PAYLOAD, line: 1 },
      producer: 'adversarial-test',
      confidenceTier: 'high',
      snippet: IMG_ONERROR,
      timestamp: null,
      commit: null,
      limitations: [],
      conflict: null,
    },
  ],
  coverage: {},
  limitations: [SCRIPT_TAG, LONG_IDENTIFIER],
  extensions: {},
});
