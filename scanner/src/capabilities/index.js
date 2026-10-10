// Public surface of the capability facility (X-501 to X-504). Consumers import
// from here; nothing in the default scan or report path does.
export {
  MANIFEST_SCHEMA, MANIFEST_SCHEMA_VERSION, ARG_MODES, RESOURCE_RANGES,
  validateManifest, bindManifest, manifestDigest, deriveChild,
} from './manifest.js';
export { decide, classifyExecutable } from './decide.js';
export { REASONS, REASON_CODES, reasonText, sanitizeSubject } from './reasons.js';
export { toCapabilityDecisionRecord, advise } from './records.js';
export { redactOutbound, sanitizeLogText, destinationClass, denialRecord, recordNetworkDenial } from './outbound.js';
export { startMediationProxy } from './proxy.js';
export {
  CAPABILITY_CONTROLS, probeCapabilityControls, requiredControlsFor, isAdvertisedBackend, platformStatements,
  resetCapabilityProbeCache,
} from './probes.js';
export { buildCapabilityReport, REPORT_LIMITATIONS } from './report.js';
export { runCapabilityTask } from './runner.js';
export { evaluateManifestEgress } from './egress.js';
// X-505 to X-508.
export { TOOL_CAPABILITIES, toolCapabilityFor, isMutatingOrExternal } from './tool-registry.js';
export { createToolGate, featureEnabledByOperator } from './tool-gate.js';
export { delegate, createDelegationRegistry } from './delegate.js';
export { actionForToolUse, adviseToolUse } from './hook-advice.js';
export {
  proposeChange, mediate, createDenialGuard, signPolicyGrant, applyPolicyChange, applyChangeToManifest, createPolicyLedger,
  verifyLedgerEntries, DEFAULT_RETRY_LIMIT, MAX_RETRY_LIMIT,
} from './recovery.js';
export {
  createReceiptRecorder, receiptsFromRun, verifyChainIntegrity, assessCompleteness, signReceiptChain, verifyReceiptEnvelope,
  receiptReport, receiptDirectoryConflict, writeReceiptEnvelope, readReceiptEnvelope,
} from './receipts.js';
export { ATTACK_CLASSES, KNOWN_LIMITS, buildAttackCoverage, enforcedModeReleaseGate } from './attack-coverage.js';
