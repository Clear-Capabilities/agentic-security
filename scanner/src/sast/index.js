// SAST submodule view of the engine — file-level static analysis.
export {
  performAnalysis, performASTAnalysis, performRegexAnalysis,
  scanRoutes, scanLogicVulns, scanStructuralVulns, scanExtraStructural,
  scanReDoS, scanCiphers, scanGraphQL,
  buildImportGraph, crossFileTaint, buildStoredTaintRegistry, crossStoredTaint,
  crossSessionTaint, buildCallGraph, annotateReachability, detectGuardsForFinding,
  inferSanitizers, applyLearnedSanitizers, applySanitizerEffectiveness,
  crossFindingChain, classifyOrphans, classifyField, classifyEndpoint,
  scoreTriage, dedupeFindingsWithEvidence,
  SOURCE_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS, ROUTE_PATTERNS,
  LOGIC_PATTERNS, STRUCTURAL_VULN_PATTERNS, EXTRA_STRUCTURAL_PATTERNS,
  CHAIN_RULES, GRAPHQL_VULN_PATTERNS, GUARD_PATTERNS,
  SANITIZER_EFFECTIVENESS, SEVERITY_SCORE,
  CIPHER_REST_PATTERNS, CIPHER_TRANSIT_PATTERNS,
  DATA_CLASSES,
} from '../engine.js';
