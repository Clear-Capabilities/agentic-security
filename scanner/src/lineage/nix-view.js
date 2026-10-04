// Nix configuration lineage (X-004 / X-005). Contributes nodes, data elements, edges, flows and evidence to an
// EXISTING DataFlowGraph v1; it never forks the schema. The inputs are the NIX-006 secret-placement findings
// (which already include secrets interpolated into generated scripts), so a credential-bearing option is followed
// to where the Nix evaluation puts it: the world-readable store, a derivation environment, a log, or the source
// file itself.
//
// Scope and honesty:
//   * Every contribution is STATIC CONFIGURATION evidence. A node carries `analysis: {language: 'nix',
//     kind: 'configuration', scope: 'static-configuration', runtime: false}`: a declared service or a store
//     path is not proof that a value is exposed at runtime, and nothing here claims it is.
//   * A runtime reference (a `…File` option, EnvironmentFile, sops/agenix path) is not a flow; the secret analyzer
//     already treats it as safe and so does this view.
//   * The original location is the Nix source; a generated-script location is kept as `generatedLocation` when the
//     value lands in a generated shell script. Neither is invented.
//   * No application-level link is inferred: a Nix store file does not become an application read by name.

import * as ids from './ids.js';
import { classifyDataElementName } from './classification.js';
import { analyzeNixSecrets } from '../language/nix-secrets.js';
import { analyzeNixPersonalData, destinationOf } from '../language/nix-privacy.js';

export const NIX_VIEW_VERSION = 'nix-lineage/1';

const ANALYSIS = Object.freeze({ language: 'nix', kind: 'configuration', scope: 'static-configuration', runtime: false });

// exposure -> sink decision. Each is a registry-shaped decision (kind + subtype), never a call site.
const SINKS = {
  store: { kind: 'store', subtype: 'file', label: 'Nix store (world-readable)', stage: 'storage' },
  build: { kind: 'store', subtype: 'file', label: 'Derivation environment (recorded in the .drv)', stage: 'storage' },
  log: { kind: 'log', subtype: 'log', label: 'Evaluation or script log output', stage: 'storage' },
  'plaintext-source': { kind: 'store', subtype: 'file', label: 'Configuration source file', stage: 'storage' },
};

const lastSegment = (detail) => String(detail || '').replace(/^option\s+/, '').replace(/^config\./, '').split('.').filter(Boolean).pop() || 'secret';

/**
 * Adds Nix configuration lineage to `graph` in place. Returns `{added, nixFiles, gaps}`.
 * @param {object} graph a DataFlowGraph v1 (mutated)
 * @param {Record<string,string>} files every file handed to the scan
 * @param {{repository?: string}} opts
 */
export function contributeNixConfigLineage(graph, files, opts = {}) {
  const nixFiles = Object.keys(files || {}).filter((f) => /\.nix$/i.test(f));
  const result = { added: { nodes: 0, edges: 0, flows: 0, dataElements: 0 }, nixFiles: nixFiles.length, gaps: [] };
  if (!nixFiles.length) return result;
  const repository = opts.repository || '';
  let analysis;
  try { analysis = analyzeNixSecrets({ files }); } catch (e) { result.gaps.push(`nix secret analysis failed: ${String((e && e.message) || e)}`); return result; }
  result.gaps.push(...(analysis.gaps || []).map((g) => (typeof g === 'string' ? g : (g && (g.reason || g.message)) || 'unresolved Nix construct')));

  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const els = new Map(graph.dataElements.map((d) => [d.id, d]));
  const edges = new Map(graph.edges.map((e) => [e.id, e]));
  const flows = new Map(graph.flows.map((f) => [f.id, f]));
  const evidence = new Map(graph.evidence.map((e) => [e.id, e]));

  const mint = (kind, subtype, label, stage, externality = 'internal') => {
    const id = ids.nodeId(kind, [repository, `nix:${subtype}`, 'modeled', externality, '']);
    let n = nodes.get(id);
    if (!n) {
      n = {
        id, kind, subtype, label, aliases: [], location: null,
        system: { application: repository, environment: null }, destination: null, storeDetail: null, queueDetail: null,
        externality: { value: externality, evidenceRefs: [] }, lifecycleStages: [stage], governanceRefs: {},
        dataElementIds: [], evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, coverageStatus: 'modeled', coverageReason: null,
        analysis: ANALYSIS,
      };
      nodes.set(id, n); result.added.nodes++;
    }
    return n;
  };
  const source = mint('source', 'declared', 'Nix configuration value', 'collection');

  for (const f of analysis.findings || []) {
    const sink = SINKS[f.exposure];
    if (!sink || !f.source) continue;                                   // runtime references and unclassified exposures are not flows
    const name = lastSegment(f.source.detail);
    const deId = ids.dataElementId(name, [repository, f.source.file || f.file || '']);
    let de = els.get(deId);
    if (!de) {
      const cls = classifyDataElementName(name).classes;
      de = {
        id: deId, name, aliases: [], declaredType: null, dataClasses: cls.length ? cls : ['CREDENTIALS'], aiContexts: [],
        sourceLocations: [{ file: f.source.file || f.file, line: f.line, scope: 'nix', path: f.source.detail }],
        dataSubjectCategory: null, classificationEvidence: [], manualOverride: false,
      };
      els.set(deId, de); result.added.dataElements++;
    }
    const snk = mint(sink.kind, sink.subtype, sink.label, sink.stage);
    if (!source.dataElementIds.includes(deId)) source.dataElementIds.push(deId);
    if (!snk.dataElementIds.includes(deId)) snk.dataElementIds.push(deId);

    const edgeIdStr = ids.edgeId(source.id, snk.id, 'data_flow', [f.source.detail, f.exposure, deId, 'identity']);
    if (!edges.has(edgeIdStr)) {
      edges.set(edgeIdStr, {
        id: edgeIdStr, from: source.id, to: snk.id, relationship: 'data_flow',
        fieldMappings: [{ fromPath: f.source.detail, toPath: null, dataElementIds: [deId], mappingType: 'identity', transformationIds: [] }],
        protocol: { name: 'nix-evaluation', destinationResolution: 'resolved_from_config' },
        boundaryCrossings: [], provenance: 'code',
        protection: { transit: { verdict: 'not_applicable', evidenceGrade: 'none' }, atRest: { verdict: f.exposure === 'log' ? 'not_assessed' : 'unprotected', evidenceGrade: 'config' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: [], coverageStatus: 'modeled', analysis: ANALYSIS,
      });
      result.added.edges++;
    }
    const claim = `${f.rule}: ${f.source.detail} reaches ${sink.label}`;
    const evId = ids.evidenceId(claim, `${f.file}:${f.line}`, [deId, f.exposure]);
    if (!evidence.has(evId)) {
      evidence.set(evId, {
        id: evId, claim, evidenceType: 'configuration', location: { file: f.file, line: f.line, column: f.column ?? null, generatedLocation: f.generatedLocation || null },
        producer: 'nix-secrets', confidenceTier: null, snippet: null, timestamp: null, commit: null,
        limitations: ['static configuration evidence: the value is not proven to be present on a running host'], conflict: null,
      });
    }
    const fId = ids.flowId(source.id, snk.id, [deId], [f.exposure, f.rule]);
    if (!flows.has(fId)) {
      flows.set(fId, {
        id: fId, dataElementIds: [deId], source: source.id, sink: snk.id, edgeIds: [edgeIdStr], transformationIds: [],
        alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: f.exposure === 'log' ? 'not_assessed' : 'unprotected',
        evidenceRefs: [evId], confidence: { score: 0.8, tier: 'high' }, coverageStatus: 'modeled', findingRefs: [], governanceRefs: {},
        limitations: ['static Nix configuration evidence', ...(f.generatedLocation ? ['the value lands in a generated script; both the original and generated locations are recorded'] : [])],
        evidenceGrade: 'explicit', handling: 'raw', analysis: ANALYSIS,
      });
      result.added.flows++;
    } else {
      const ex = flows.get(fId);
      if (!ex.evidenceRefs.includes(evId)) ex.evidenceRefs.push(evId);
    }
  }

  // Personal data (PII, PHI, PCI, financial) written into configuration: a field-to-store flow per unprotected reference.
  let personal = { references: [], gaps: [] };
  try { personal = analyzeNixPersonalData({ files }); } catch (e) { result.gaps.push(`nix personal-data analysis failed: ${String((e && e.message) || e)}`); }
  result.gaps.push(...personal.gaps);
  for (const ref of personal.references) {
    if (ref.protected) continue;                                    // hashed, measured or only compared: no flow of the value
    const dest = destinationOf(ref.attr);
    const sink = { kind: 'store', subtype: 'file', label: dest.label, stage: 'storage' };
    const deId = ids.dataElementId(ref.field, [repository, ref.file]);
    let de = els.get(deId);
    if (!de) {
      de = {
        id: deId, name: ref.field, aliases: [], declaredType: null, dataClasses: ref.classes, aiContexts: [],
        sourceLocations: [{ file: ref.file, line: ref.line, scope: 'nix', path: ref.option }],
        dataSubjectCategory: null, classificationEvidence: [], manualOverride: false,
      };
      els.set(deId, de); result.added.dataElements++;
    }
    const snk = mint(sink.kind, sink.subtype, sink.label, sink.stage);
    if (!source.dataElementIds.includes(deId)) source.dataElementIds.push(deId);
    if (!snk.dataElementIds.includes(deId)) snk.dataElementIds.push(deId);
    const edgeIdStr = ids.edgeId(source.id, snk.id, 'data_flow', [ref.option, 'personal-data', deId, 'identity']);
    if (!edges.has(edgeIdStr)) {
      edges.set(edgeIdStr, {
        id: edgeIdStr, from: source.id, to: snk.id, relationship: 'data_flow',
        fieldMappings: [{ fromPath: ref.option, toPath: ref.attr.join('.'), dataElementIds: [deId], mappingType: 'identity', transformationIds: [] }],
        protocol: { name: 'nix-evaluation', destinationResolution: 'resolved_from_config' },
        boundaryCrossings: [], provenance: 'code',
        protection: { transit: { verdict: 'not_applicable', evidenceGrade: 'none' }, atRest: { verdict: 'unprotected', evidenceGrade: 'config' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: [], coverageStatus: 'modeled', analysis: ANALYSIS,
      });
      result.added.edges++;
    }
    const claim = `nix-personal-data-in-store: ${ref.option} reaches ${sink.label}`;
    const evId = ids.evidenceId(claim, `${ref.file}:${ref.line}`, [deId, 'personal-data']);
    if (!evidence.has(evId)) {
      evidence.set(evId, {
        id: evId, claim, evidenceType: 'configuration', location: { file: ref.file, line: ref.line, column: null, generatedLocation: null },
        producer: 'nix-privacy', confidenceTier: null, snippet: null, timestamp: null, commit: null,
        limitations: ['static configuration evidence: the option may hold no real personal data, and the value is not proven present on a running host'], conflict: null,
      });
    }
    const fId = ids.flowId(source.id, snk.id, [deId], ['personal-data', ref.attr.join('.')]);
    if (!flows.has(fId)) {
      flows.set(fId, {
        id: fId, dataElementIds: [deId], source: source.id, sink: snk.id, edgeIds: [edgeIdStr], transformationIds: [],
        alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'unprotected',
        evidenceRefs: [evId], confidence: { score: 0.7, tier: 'medium' }, coverageStatus: 'modeled', findingRefs: [], governanceRefs: {},
        limitations: ['static Nix configuration evidence', 'classified by the option name only'],
        evidenceGrade: 'inferred', handling: 'raw', analysis: ANALYSIS,
      });
      result.added.flows++;
    } else {
      const ex = flows.get(fId);
      if (!ex.evidenceRefs.includes(evId)) ex.evidenceRefs.push(evId);
    }
  }

  const byId = (a, b) => (a.id < b.id ? -1 : 1);
  graph.nodes = [...nodes.values()].sort(byId);
  graph.dataElements = [...els.values()].sort(byId);
  graph.edges = [...edges.values()].sort(byId);
  graph.flows = [...flows.values()].sort(byId);
  graph.evidence = [...evidence.values()].sort(byId);
  if (result.added.flows) {
    graph.limitations = [...graph.limitations, 'Nix configuration lineage is static: a store path or declared service is not proof of runtime exposure.'];
  }
  return result;
}
