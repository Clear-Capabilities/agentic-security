//
// Generates the deterministic flagship DataFlowGraph v1 fixture (Data
// Flow Explorer PRD Appendix D.2/D.3 — the synthetic "payments-platform"
// application). Run with `node build-flagship-fixture.mjs` from anywhere;
// writes flagship-graph.json next to this script. Re-running must
// produce byte-identical output (AC-14) — there is no Date.now()/random
// anywhere in this file; `generatedAt` is a fixed synthetic timestamp,
// per Appendix D.1's rule that fixture content can never leak
// non-reproducible values into what looks like a real scan artifact.
//
// PRD Appendix D.1: "Production UI code may not contain special cases
// keyed to fixture filenames, node names, endpoints, commits, authors, or
// expected verdicts." This generator is the ONE place fixture-specific
// facts are allowed to live; `graph.extensions.fixtureNodeKeys` /
// `fixtureFlowKeys` give tests and (later) UI fixtures a genuinely
// generic lookup table rather than hardcoded ids, without smuggling
// fixture-awareness into scanner/src/lineage's own production modules.
//
// One deliberate extension beyond Appendix D.2's literal 13-row table:
// D.3's flow.pii.analytics path text reads "Support/Registration source
// -> Events Service -> Analytics DB/Provider", naming an "Events Service"
// hop that has no row of its own in D.2. Rather than silently reusing an
// unrelated node for that role, this generator adds one extra node
// (node.events) to make the path the PRD itself describes actually
// representable. Documented here, not hidden.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { emptyGraphEnvelope } from '../schema.js';
import { graphId, nodeId, dataElementId, edgeId, flowId, transformationId, evidenceId } from '../ids.js';
import { emptyProtection } from '../protection.js';
import { classifyDataElementName } from '../classification.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = 'payments-platform';
const COMMIT = 'fixture0000000000000000000000000000000';
const GENERATED_AT = '2026-08-29T00:00:00.000Z';

function node({ key, kind, subtype, label, aliases = [], lifecycleStages = [], externality = 'internal', dataElementIds = [] }) {
  const id = nodeId(kind, [REPO, key]);
  return {
    id, kind, subtype, label, aliases,
    location: null,
    system: { application: REPO, environment: 'production' },
    destination: null,
    externality: { value: externality, evidenceRefs: [] },
    lifecycleStages, governanceRefs: {}, dataElementIds, evidenceRefs: [],
    confidence: { score: 1, tier: 'high' },
    coverageStatus: 'modeled',
  };
}

function dataElement(name, discriminator) {
  const { classes } = classifyDataElementName(name);
  return {
    id: dataElementId(name, [REPO, discriminator]),
    name, aliases: [], declaredType: null,
    dataClasses: classes, aiContexts: [],
    sourceLocations: [], dataSubjectCategory: null,
    classificationEvidence: [], manualOverride: false,
    firstSeenProvenance: { commit: COMMIT, note: 'fixture evidence only, not default production content' },
  };
}

function edge({ from, to, mappings = [], protocolName = 'in-process', destinationResolution = 'literal', boundaryCrossings = [], protection = emptyProtection() }) {
  // Discriminator includes toPath values and all dataElementIds carried in the mapping.
  // Sort dataElementIds for determinism (matching flowId approach in ids.js).
  const allDataElementIds = mappings.length > 0
    ? [...new Set(mappings.flatMap((m) => m.dataElementIds || []))].sort()
    : [];
  const toPathValues = mappings.map((m) => m.toPath);
  const discriminatorParts = [...toPathValues, ...allDataElementIds];
  return {
    id: edgeId(from, to, 'data_flow', discriminatorParts),
    from, to, relationship: 'data_flow',
    fieldMappings: mappings,
    protocol: { name: protocolName, destinationResolution },
    boundaryCrossings, provenance: 'code', protection, evidenceRefs: [], coverageStatus: 'modeled',
  };
}

function flow({ dataElementIds, source, sink, edgeIds, transformationIds = [], policyVerdict, protectionSummary, discriminator = [], governanceRefs = {}, limitations = [] }) {
  return {
    id: flowId(source, sink, dataElementIds, discriminator),
    dataElementIds, source, sink, edgeIds, transformationIds,
    alternatePathCount: 0, policyVerdict, protectionSummary,
    evidenceRefs: [], confidence: { score: 1, tier: 'high' },
    coverageStatus: 'modeled', findingRefs: [], governanceRefs, limitations,
  };
}

function build() {
  const graph = emptyGraphEnvelope({
    graphId: graphId({ repository: REPO, commit: COMMIT, configHash: 'fixture-default' }),
    generatedAt: GENERATED_AT,
    scope: { source: 'fixture', repository: REPO, commit: COMMIT, environment: 'production' },
  });

  // --- Data elements (defined first: node.dataElementIds below is derived
  // from which elements actually flow through each node per the edges/
  // flows this generator builds, never guessed independently of them) ---
  const cardNumber = dataElement('card_number', 'payments');
  const diagnosis = dataElement('diagnosis', 'support');
  const email = dataElement('email', 'events');
  const cardIds = [cardNumber.id];
  const phiIds = [diagnosis.id];
  const piiIds = [email.id];

  // --- Nodes (Appendix D.2 + the documented node.events extension) ---
  // dataElementIds per node is derived from the edges/flows below: web is
  // the shared collection point for all three elements; payments/logs/
  // postgres/payment_api/ai/model see card_number (the PCI path fans out
  // to log/db/external-API/AI sinks); ai/model/vector see diagnosis (the
  // PHI-plus-AI path); events/analytics/unresolved see email (the PII
  // path). gateway/retention/deletion have no data-carrying edge in this
  // fixture (retention/deletion are declared process steps, not data-flow
  // hops — see the comment at their edges below), so they stay empty.
  const web = node({ key: 'web', kind: 'source', subtype: 'web-app', label: 'Web App', aliases: ['Checkout Form', 'Registration Form'], lifecycleStages: ['collection'], externality: 'internal', dataElementIds: [cardNumber.id, diagnosis.id, email.id] });
  const gateway = node({ key: 'gateway', kind: 'api', subtype: 'api-gateway', label: 'API Gateway', lifecycleStages: ['processing'] });
  const payments = node({ key: 'payments', kind: 'process', subtype: 'service', label: 'Payments Service', lifecycleStages: ['processing'], dataElementIds: [cardNumber.id] });
  const events = node({ key: 'events', kind: 'process', subtype: 'service', label: 'Events Service', lifecycleStages: ['processing'], dataElementIds: [email.id] });
  const ai = node({ key: 'ai', kind: 'process', subtype: 'ai-assistant', label: 'AI Assistant', lifecycleStages: ['processing'], dataElementIds: [cardNumber.id, diagnosis.id] });
  const postgres = node({ key: 'postgres', kind: 'store', subtype: 'postgres-table', label: 'PostgreSQL', lifecycleStages: ['storage'], dataElementIds: [cardNumber.id] });
  const logs = node({ key: 'logs', kind: 'log', subtype: 'application-logs', label: 'Application Logs', lifecycleStages: ['storage'], dataElementIds: [cardNumber.id] });
  const paymentApi = node({ key: 'payment_api', kind: 'external', subtype: 'payment-api', label: 'Payment API', aliases: ['Payment Processor'], lifecycleStages: ['sharing'], externality: 'external', dataElementIds: [cardNumber.id] });
  const analytics = node({ key: 'analytics', kind: 'external', subtype: 'analytics-api', label: 'Analytics API', aliases: ['Analytics Provider', 'Analytics DB'], lifecycleStages: ['sharing'], externality: 'external', dataElementIds: [email.id] });
  const model = node({ key: 'model', kind: 'external', subtype: 'ai-model-provider', label: 'Model Provider', lifecycleStages: ['sharing'], externality: 'external', dataElementIds: [cardNumber.id, diagnosis.id] });
  const vector = node({ key: 'vector', kind: 'store', subtype: 'vector-store', label: 'Vector Store', lifecycleStages: ['storage'], externality: 'unknown', dataElementIds: [diagnosis.id] });
  const unresolved = node({ key: 'unresolved', kind: 'unresolved', subtype: 'unresolved-destination', label: 'Unresolved Destination', lifecycleStages: ['sharing'], externality: 'unknown', dataElementIds: [email.id] });
  const retention = node({ key: 'retention', kind: 'process', subtype: 'retention-policy', label: 'Retention Policy', lifecycleStages: ['retention'] });
  const deletion = node({ key: 'deletion', kind: 'process', subtype: 'deletion-job', label: 'Deletion Job', lifecycleStages: ['deletion'] });

  [web, gateway, payments, events, ai, postgres, logs, paymentApi, analytics, model, vector, unresolved, retention, deletion]
    .forEach((n) => { graph.nodes.push(n); });
  [cardNumber, diagnosis, email].forEach((d) => { graph.dataElements.push(d); });

  // --- flow.pci.masked_log: Web -> Payments -> maskCard() -> Application Logs (handling protected) ---
  const maskTransform = { id: transformationId(payments.id, 'maskCard'), inputPath: 'payment.pan', outputPath: 'maskedPan', callee: 'maskCard', location: { file: 'services/payment.js', line: 55 }, kind: 'mask', reversibility: 'irreversible', algorithm: null, appliesToAllPaths: true, controlCredit: true, controlCreditReason: 'maskCard() proven on this branch (all feasible paths)' };
  graph.transformations.push(maskTransform);
  const e1a = edge({ from: web.id, to: payments.id, mappings: [{ fromPath: 'req.body.card_number', toPath: 'payment.pan', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }] });
  const maskedProtection = emptyProtection();
  maskedProtection.handling = { verdict: 'protected', evidenceGrade: 'code' };
  const e1b = edge({ from: payments.id, to: logs.id, mappings: [{ fromPath: 'payment.pan', toPath: 'maskedPan', dataElementIds: cardIds, mappingType: 'transformation', transformationIds: [maskTransform.id] }], protection: maskedProtection, boundaryCrossings: [] });
  graph.edges.push(e1a, e1b);
  const flowMaskedLog = flow({ dataElementIds: cardIds, source: web.id, sink: logs.id, edgeIds: [e1a.id, e1b.id], transformationIds: [maskTransform.id], policyVerdict: 'not_evaluated', protectionSummary: 'protected', discriminator: ['masked-branch'] });
  graph.flows.push(flowMaskedLog);

  // --- flow.pci.raw_log: Web -> Payments -> raw logger (RAW PCI, unprotected) ---
  const e2 = edge({ from: payments.id, to: logs.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payment.pan', dataElementIds: cardIds, mappingType: 'identity', transformationIds: [] }], protection: (() => { const p = emptyProtection(); p.handling = { verdict: 'unprotected', evidenceGrade: 'code' }; return p; })() });
  graph.edges.push(e2);
  const flowRawLog = flow({ dataElementIds: cardIds, source: web.id, sink: logs.id, edgeIds: [e1a.id, e2.id], policyVerdict: 'not_evaluated', protectionSummary: 'unprotected', discriminator: ['raw-branch'], limitations: ['RAW PCI: card_number logged without masking on this branch'] });
  graph.flows.push(flowRawLog);

  // --- flow.pci.database: Web -> Payments -> payments.pan (at rest unknown) ---
  const dbProtection = emptyProtection();
  dbProtection.atRest = { verdict: 'unknown', evidenceGrade: 'none' };
  const e3 = edge({ from: payments.id, to: postgres.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payments.pan', dataElementIds: cardIds, mappingType: 'identity', transformationIds: [] }], protection: dbProtection });
  graph.edges.push(e3);
  const flowDatabase = flow({ dataElementIds: cardIds, source: web.id, sink: postgres.id, edgeIds: [e1a.id, e3.id], policyVerdict: 'not_evaluated', protectionSummary: 'unknown', limitations: ['No correlated at-rest encryption configuration found for this store'] });
  graph.flows.push(flowDatabase);

  // --- flow.pci.payment_api: Web -> Payments -> http://payments.example/charge (transit unprotected) ---
  const httpProtection = emptyProtection();
  httpProtection.transit = { verdict: 'unprotected', evidenceGrade: 'code' };
  const e4 = edge({ from: payments.id, to: paymentApi.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payload.cardNumber', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }], protocolName: 'http', destinationResolution: 'literal', boundaryCrossings: ['trust-zone:external'], protection: httpProtection });
  graph.edges.push(e4);
  const flowPaymentApi = flow({ dataElementIds: cardIds, source: web.id, sink: paymentApi.id, edgeIds: [e1a.id, e4.id], policyVerdict: 'not_evaluated', protectionSummary: 'unprotected', limitations: ['Cleartext HTTP scheme: no TLS termination evidence found'] });
  graph.flows.push(flowPaymentApi);

  // --- flow.pci.ai: Payments -> AI Assistant -> Model Provider (review) ---
  const e5a = edge({ from: payments.id, to: ai.id, mappings: [{ fromPath: 'payment.pan', toPath: 'promptContext.paymentCard', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }] });
  const e5b = edge({ from: ai.id, to: model.id, mappings: [{ fromPath: 'promptContext.paymentCard', toPath: 'model.messages[].content', dataElementIds: cardIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  graph.edges.push(e5a, e5b);
  const flowPciAi = flow({ dataElementIds: cardIds, source: web.id, sink: model.id, edgeIds: [e1a.id, e5a.id, e5b.id], policyVerdict: 'manual_review_required', protectionSummary: 'unknown', governanceRefs: { recipient: 'manual_required', purpose: 'manual_required', lawfulBasis: 'manual_required' }, limitations: ['AI recipient/purpose/retention evidence not established from code alone'] });
  graph.flows.push(flowPciAi);

  // --- flow.phi.ai: Support Form (Web) -> AI Assistant -> Model Provider + Vector Store ---
  const e6a = edge({ from: web.id, to: ai.id, mappings: [{ fromPath: 'req.body.diagnosis', toPath: 'promptContext.summary', dataElementIds: phiIds, mappingType: 'rename', transformationIds: [] }] });
  const e6b = edge({ from: ai.id, to: model.id, mappings: [{ fromPath: 'promptContext.summary', toPath: 'model.messages[].content', dataElementIds: phiIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  const e6c = edge({ from: ai.id, to: vector.id, mappings: [{ fromPath: 'promptContext.summary', toPath: 'vector.document', dataElementIds: phiIds, mappingType: 'transformation', transformationIds: [] }] });
  graph.edges.push(e6a, e6b, e6c);
  const flowPhiAi = flow({
    dataElementIds: phiIds, source: web.id, sink: model.id, edgeIds: [e6a.id, e6b.id, e6c.id],
    policyVerdict: 'manual_review_required', protectionSummary: 'unknown',
    governanceRefs: { lawfulBasis: 'manual_required', retention: 'unknown', transfer: 'review' },
    limitations: ['Lawful basis, retention, and transfer mechanism not established from code alone'],
  });
  graph.flows.push(flowPhiAi);

  // --- flow.pii.analytics: Web (Registration) -> Events Service -> Analytics API (90-day retention only if evidenced) ---
  const e7a = edge({ from: web.id, to: events.id, mappings: [{ fromPath: 'req.body.email', toPath: 'event.email', dataElementIds: piiIds, mappingType: 'rename', transformationIds: [] }] });
  const e7b = edge({ from: events.id, to: analytics.id, mappings: [{ fromPath: 'event.email', toPath: 'traits.email', dataElementIds: piiIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  graph.edges.push(e7a, e7b);
  const flowPiiAnalytics = flow({
    dataElementIds: piiIds, source: web.id, sink: analytics.id, edgeIds: [e7a.id, e7b.id],
    policyVerdict: 'not_evaluated', protectionSummary: 'unknown',
    governanceRefs: { retention: 'unknown', deletion: 'not_found' },
    limitations: ['No correlated retention/deletion policy evidence found for this recipient'],
  });
  graph.flows.push(flowPiiAnalytics);
  // Retention/deletion process nodes are wired for the fixture's governance
  // story even without a resolved edge protection verdict — they represent
  // declared process steps, not a data-flow edge with its own verdict.
  graph.edges.push(edge({ from: analytics.id, to: retention.id, mappings: [] }));
  graph.edges.push(edge({ from: retention.id, to: deletion.id, mappings: [] }));

  // --- flow.pii.unresolved: inbound source -> dynamic outbound call ---
  const e8 = edge({ from: web.id, to: unresolved.id, mappings: [{ fromPath: 'req.body.email', toPath: 'unknown', dataElementIds: piiIds, mappingType: 'unknown', transformationIds: [] }], destinationResolution: 'dynamic', boundaryCrossings: ['trust-zone:unknown'] });
  graph.edges.push(e8);
  const flowUnresolved = flow({
    dataElementIds: piiIds, source: web.id, sink: unresolved.id, edgeIds: [e8.id],
    policyVerdict: 'not_evaluated', protectionSummary: 'unknown',
    limitations: ['Destination computed from an unresolved runtime value (dynamic URL expression)'],
  });
  graph.flows.push(flowUnresolved);

  // --- Evidence (one representative entry per flow, matching PRD 16's
  // four-question shape). Each entry is the evidence FOR the protection
  // verdict on the specific edge/flow named in its claim, so it is wired
  // back via evidenceRefs on that edge and that flow — an evidence object
  // nothing references is structurally orphaned and proves nothing.
  function evidence(claim, evType, note) {
    return { id: evidenceId(claim, note), claim, evidenceType: evType, location: { note }, producer: 'lineage-fixture-builder', confidenceTier: 'high', snippet: null, timestamp: GENERATED_AT, commit: COMMIT, limitations: [], conflict: false };
  }
  const evMaskedLog = evidence('card_number reaches Application Logs via maskCard() on the masked branch', 'code', 'services/payment.js:55');
  const evRawLog = evidence('card_number reaches Application Logs raw on a separate branch', 'code', 'services/payment.js:60');
  const evDatabase = evidence('card_number reaches payments.pan with no correlated at-rest configuration', 'code', 'services/payment.js:70');
  const evPaymentApi = evidence('card_number reaches http://payments.example/charge over cleartext HTTP', 'code', 'clients/gateway.js:72');
  graph.evidence.push(evMaskedLog, evRawLog, evDatabase, evPaymentApi);

  e1b.evidenceRefs = [evMaskedLog.id];
  flowMaskedLog.evidenceRefs = [evMaskedLog.id];
  e2.evidenceRefs = [evRawLog.id];
  flowRawLog.evidenceRefs = [evRawLog.id];
  e3.evidenceRefs = [evDatabase.id];
  flowDatabase.evidenceRefs = [evDatabase.id];
  e4.evidenceRefs = [evPaymentApi.id];
  flowPaymentApi.evidenceRefs = [evPaymentApi.id];

  graph.coverage = { languages: [{ language: 'js', filesExpected: 6, filesAnalyzed: 6 }], parseFailures: [], destinationResolutionStatus: 'complete-for-fixture', pathBudgetTruncation: false };
  graph.limitations = ['This is a synthetic fixture graph, not a real repository scan. See scope.source.'];
  graph.scanHealth = { status: 'complete', reason: 'fixture' };
  graph.taxonomy = { version: '1.0.0', source: 'built-in + CONFIDENTIAL extension' };

  graph.extensions = {
    fixtureNodeKeys: {
      'node.web': web.id, 'node.gateway': gateway.id, 'node.payments': payments.id,
      'node.ai': ai.id, 'node.postgres': postgres.id, 'node.logs': logs.id,
      'node.payment_api': paymentApi.id, 'node.analytics': analytics.id, 'node.model': model.id,
      'node.vector': vector.id, 'node.unresolved': unresolved.id, 'node.retention': retention.id,
      'node.deletion': deletion.id, 'node.events': events.id,
    },
    fixtureFlowKeys: {
      'flow.pci.masked_log': flowMaskedLog.id, 'flow.pci.raw_log': flowRawLog.id,
      'flow.pci.database': flowDatabase.id, 'flow.pci.payment_api': flowPaymentApi.id,
      'flow.pci.ai': flowPciAi.id, 'flow.phi.ai': flowPhiAi.id,
      'flow.pii.analytics': flowPiiAnalytics.id, 'flow.pii.unresolved': flowUnresolved.id,
    },
  };

  return graph;
}

function main() {
  const graph = build();
  const outPath = path.join(__dirname, 'flagship-graph.json');
  fs.writeFileSync(outPath, JSON.stringify(graph, null, 2) + '\n');
  console.log(`wrote ${outPath}`);
}

main();
