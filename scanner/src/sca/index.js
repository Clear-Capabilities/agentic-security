// SCA submodule view of the engine — dependency vulnerability + reachability.
export {
  parseManifests, queryOSV, queryRegistries,
  buildReachabilitySet, computeAttackPathComponents,
  markUsedVulnFunctions, VULN_FUNCTION_HINTS,
} from '../engine.js';
