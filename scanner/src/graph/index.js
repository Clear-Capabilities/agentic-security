// Typed graph views and identity crosswalks (DAG-06). See CLAUDE.md in this directory.
export * from './refs.js';
export * from './relations.js';
export { IndexedGraphView, local, foreign, adjacencyCacheStats, clearAdjacencyCache } from './view.js';
export { provenanceView, PROVENANCE_ADAPTER_VERSION } from './adapters/provenance.js';
export { dataflowView, DATAFLOW_ADAPTER_VERSION } from './adapters/dataflow.js';
export { semanticView, SEMANTIC_ADAPTER_VERSION } from './adapters/semantic.js';
export { artifactView, ARTIFACT_ADAPTER_VERSION } from './adapters/artifact.js';
export { crossRepoLinkView, findingsView, CROSSREPO_ADAPTER_VERSION, FINDINGS_ADAPTER_VERSION } from './adapters/crossrepo.js';
export { createGraphRegistry, SUPPORTED_ADAPTER_MAJORS } from './registry.js';
export { createCrosswalk, CROSSWALK_VERSION, MAPPING_TYPES } from './crosswalk.js';
export {
  mapFindingsToCallSites, mapCallSitesToWitnesses, mapWitnessesToFlows, mapProjectedNodesToSites,
} from './crosswalk-builders.js';
export { attributeObservation } from './observation.js';
