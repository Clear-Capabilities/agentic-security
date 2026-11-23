// Per-file and per-analyzer coverage ledgers (assurance-hardening PRD FR-203).
//
// "Every in-scope file has exactly one terminal coverage status for every
// applicable required analyzer." Built on top of FR-201 (every detector call
// site isolated via runDetector, capturing {file, analyzer, err} into
// _detectorErrors) and FR-202 (real deadline enforcement, marking a file
// _timeout:true when its cascade was preemptively killed).
//
// D-0051's grounding (cycle 80) found the real applicability shape by
// auditing every runFileCascade call site directly, not by guessing from
// analyzer names: of the 121 detectors wrapped in runDetector, 110 run
// unconditionally on every file; 2 are file-extension-gated
// (scanRegexReDoS, scanGraphQL); 9 are operator-policy-gated via individual
// AGENTIC_SECURITY_NO_* env vars, all additionally nested inside one shared
// AGENTIC_SECURITY_NO_INTEGRATION gate. This module encodes exactly that
// shape as data, so a coverage claim can be COMPUTED, not asserted.
//
// PRD section 10.2's allowed AnalyzerResult statuses are `completed`,
// `partial`, `failed`, `timed_out`, `skipped_by_policy`, `unavailable`.
// This module emits four of the six: `completed` (ran without throwing),
// `failed` (captured in _detectorErrors), `timed_out` (the file's whole
// cascade was preemptively killed -- see below for why that means EVERY
// analyzer on that file, not just one), `skipped_by_policy` (an operator
// env-var disabled it for the whole scan). `partial` and `unavailable` are
// deliberately not emitted: nothing in this codebase's detector model
// currently produces a partial-completion or environment-unavailable
// signal per analyzer, and fabricating one would be exactly the "looks
// more precise than the underlying analysis supports" failure this PRD
// item exists to prevent (see scan-health.js's own header for the same
// discipline applied to its `analyzers: null` placeholder this module
// replaces).
//
// WHY A FILE TIMEOUT MARKS EVERY ANALYZER ON THAT FILE, NOT JUST ONE:
// FR-202's preemptive kill (worker.terminate()) operates on the WHOLE
// per-file cascade as one unit -- there is no per-analyzer sub-deadline,
// so a killed file genuinely has no completion information for any
// analyzer that would have run on it. Reporting some of them as
// "completed" would be fabricating certainty the kill destroyed.

// The full roster, extracted directly from engine.js's runFileCascade
// (grep for `runDetector(_detectorErrors,p,'...'`) -- kept in sync by
// test/coverage-ledger-completeness.test.js, which fails if engine.js
// gains or loses a wrapped call site this list doesn't reflect.
export const ANALYZER_NAMES = Object.freeze([
  'scanAgentToolEscalation', 'scanAgentUntrustedFlow', 'scanAliasedSinks', 'scanAuthProvider',
  'scanAuthZ', 'scanAuthzSubjectConsistency', 'scanBusinessLogic', 'scanCSRF', 'scanCSharp', 'scanCachePoisoning',
  'scanClaudeHookInjection', 'scanClaudeMdPromptInjection', 'scanClaudeSettings', 'scanClientSide',
  'scanCloudIam', 'scanCloudTemplates', 'scanCodeInjectionMultilang', 'scanCodegenSink',
  'scanComparisonSafety', 'scanContainer', 'scanCpp', 'scanCppDataflow', 'scanCredentials',
  'scanCryptoProtocol', 'scanCryptoSpecialist', 'scanCsharpStructural', 'scanCsvInjection',
  'scanDappFrontend', 'scanDartFlutter', 'scanDatabaseRLS', 'scanDbTaint', 'scanDefiDeep',
  'scanDjangoHardening', 'scanEntropySecrets', 'scanEnvHygiene', 'scanEventEntrypoints',
  'scanExtraStructural', 'scanFastapiHardening', 'scanFileUpload', 'scanFrontendHygiene',
  'scanGoExtended', 'scanGoStructural', 'scanGraphQL', 'scanGraphQLModule', 'scanHostHeader',
  'scanIaC', 'scanInstallScripts', 'scanJNDI', 'scanJavaBenchExtras', 'scanJavaDeserialization',
  'scanJavaSAST', 'scanJavaStructural', 'scanJsFrameworkStructural', 'scanJulietShape',
  'scanJwtExp', 'scanK8sAdmission', 'scanKotlin', 'scanLDAPInjection', 'scanLanguageSecretConcat', 'scanLLM', 'scanLLMOwasp',
  'scanLaravelHardening', 'scanLlmApp', 'scanLlmCost', 'scanLlmRedteam', 'scanLlmTradingAgent',
  'scanLogicVulns', 'scanMCP', 'scanMassAssignment', 'scanMiddlewareOrdering', 'scanMlSupplyChain',
  'scanMobile', 'scanMobileManifest', 'scanModelLoad', 'scanMutationXSS', 'scanNoSQLInjection',
  'scanNullByteInjection', 'scanOpenRedirect', 'scanOwnershipAuthz', 'scanPhp', 'scanPipeline',
  'scanPqc', 'scanPromptFirewall', 'scanPromptTemplate', 'scanPrototypePollution', 'scanPrototypePollutionStructural', 'scanRubyHtmlInterpolation',
  'scanPythonSinks', 'scanPythonStructural', 'scanQuarkusHardening', 'scanRAGPoisoning',
  'scanRateLimit', 'scanReDoS', 'scanRedirectToctou', 'scanRegexReDoS', 'scanResourceExhaustion',
  'scanResponseSplitting', 'scanRoutes', 'scanRuby', 'scanRubyPathJoin', 'scanRust',
  'scanSSRFCloudMetadata', 'scanSSTI', 'scanSanitizerContextMismatch', 'scanSecretConcat',
  'scanSensitiveDataLogging', 'scanSiblingGuard', 'scanSolidity', 'scanSpringbootHardening',
  'scanStoredPromptInjection', 'scanStoredTaint', 'scanStructuralVulns', 'scanSwift', 'scanTOCTOU',
  'scanTerraform', 'scanTodosNearSecurity', 'scanWeakPasswordHash', 'scanWeakRandomness',
  'scanWeb3Advanced', 'scanWebhook', 'scanWrongContextSanitizer', 'scanUrlSchemeDenylist', 'scanXPathInjection', 'scanXXE',
  'scanXssReflectedMultilang', 'scanZipSlip',
  'scanLiteralEscaping', 'scanFrontmatterEngine', 'scanGitOptionInjection', 'scanRubyKernelOpen', 'scanWeakLocalPathGuard',
  'scanPhpStreamRedirect',
  'scanWeakHashCacheKey', 'scanRailsSkipAuthFilter', 'scanFilterEnforceAsymmetry', 'scanReadPermissionWrite',
  'scanNondominatingAuthzCheck', 'scanJsbnSecureRandom', 'scanEmptyHmacKey', 'scanRedirectCredentialForwarding',
  'scanPathFileHandling', 'scanDecompressionBomb', 'scanDecodedLength', 'scanReceiveLoopException',
  'scanJsMarkupMarkSafe', 'scanJsMixedTextMarkup', 'scanJsIncompleteRegexEscape', 'scanJsExecParamInterpolation', 'scanPythonRunWrittenCode',
  'scanPhpHtmlAttrInterpolation',
  'scanSourceTargetAuthz', 'scanOAuthEmailAccountLink', 'scanAccountExistenceOracle',
  'scanRequestSizedResource', 'scanResourceLimitDisabled',
]);

// File-extension applicability gates -- an analyzer NOT in this map is
// always applicable (the 110/121 default case).
export const EXTENSION_GATED_ANALYZERS = Object.freeze({
  scanRegexReDoS: /\.(?:java|cs|kt|py|php|phtml)$/i,
  scanGraphQL: /\.(graphql|gql)$/i,
  scanLanguageSecretConcat: /\.(?:l?hs|hs-boot|hsc|nix)$/i,
});

// Operator-policy gates: each also requires POLICY_GATED_OUTER_FLAG unset.
export const POLICY_GATED_ANALYZERS = Object.freeze({
  scanLlmApp: 'AGENTIC_SECURITY_NO_LLM_APP',
  scanMobile: 'AGENTIC_SECURITY_NO_MOBILE',
  scanPqc: 'AGENTIC_SECURITY_NO_PQC',
  scanWeb3Advanced: 'AGENTIC_SECURITY_NO_WEB3_ADV',
  scanDappFrontend: 'AGENTIC_SECURITY_NO_DAPP',
  scanCloudIam: 'AGENTIC_SECURITY_NO_CLOUD_IAM',
  scanK8sAdmission: 'AGENTIC_SECURITY_NO_K8S_ADM',
  scanCryptoProtocol: 'AGENTIC_SECURITY_NO_CRYPTO_PROTO',
  scanMlSupplyChain: 'AGENTIC_SECURITY_NO_ML_SUPPLY',
});

export const POLICY_GATED_OUTER_FLAG = 'AGENTIC_SECURITY_NO_INTEGRATION';

function _isDisabledByPolicy(name, env) {
  const innerVar = POLICY_GATED_ANALYZERS[name];
  if (!innerVar) return false;
  if (env[POLICY_GATED_OUTER_FLAG] === '1') return true;
  return env[innerVar] === '1';
}

/**
 * Is `analyzerName` even in scope for `file`? False only for an
 * extension-gated analyzer whose pattern the file does not match --
 * policy-gated analyzers are still "applicable" (they are just
 * `skipped_by_policy`, a real terminal status, not excluded from the
 * ledger the way a wrong file extension is).
 */
export function isAnalyzerApplicable(analyzerName, file) {
  const pattern = EXTENSION_GATED_ANALYZERS[analyzerName];
  if (!pattern) return true;
  return pattern.test(file);
}

/**
 * @param {object} input
 * @param {string[]} input.files - every file the scan actually attempted (post
 *   size/density skip -- a file the engine never opened has no coverage row
 *   at all, since no analyzer was ever in a position to run on it).
 * @param {Array<{file:string, analyzer:string, err:string}>} [input.detectorErrors]
 * @param {string[]} [input.timedOutFiles] - files whose entire cascade was
 *   preemptively killed (FR-202). Every applicable analyzer for these files
 *   becomes 'timed_out', never 'completed'.
 * @param {Record<string,string>} [input.env] - defaults to process.env;
 *   injectable for tests.
 * @returns {{byAnalyzer: object, byFile: object}}
 */
export function computeCoverageLedger({ files = [], detectorErrors = [], timedOutFiles = [], env = process.env } = {}) {
  const timedOut = new Set(timedOutFiles);
  const failedSet = new Set(
    (detectorErrors || []).filter(e => e && e.file && e.analyzer).map(e => `${e.file} ${e.analyzer}`)
  );

  const byFile = {};
  const byAnalyzer = {};
  for (const name of ANALYZER_NAMES) {
    byAnalyzer[name] = {
      applicability: EXTENSION_GATED_ANALYZERS[name] ? 'extension' : (POLICY_GATED_ANALYZERS[name] ? 'policy' : 'always'),
      filesExpected: 0, filesCompleted: 0, filesFailed: 0, filesTimedOut: 0, filesSkippedByPolicy: 0,
    };
  }

  for (const file of files) {
    const row = {};
    for (const name of ANALYZER_NAMES) {
      if (!isAnalyzerApplicable(name, file)) continue; // not in scope for this file at all
      const agg = byAnalyzer[name];
      agg.filesExpected += 1;
      let status;
      if (_isDisabledByPolicy(name, env)) {
        status = 'skipped_by_policy';
        agg.filesSkippedByPolicy += 1;
      } else if (timedOut.has(file)) {
        status = 'timed_out';
        agg.filesTimedOut += 1;
      } else if (failedSet.has(`${file} ${name}`)) {
        status = 'failed';
        agg.filesFailed += 1;
      } else {
        status = 'completed';
        agg.filesCompleted += 1;
      }
      row[name] = status;
    }
    byFile[file] = row;
  }

  return { byAnalyzer, byFile };
}

/**
 * The scan-health.js-shaped summary: PRD section 10.3's own wording
 * ("expected, attempted, completed, failed, timed-out, skipped, and
 * unavailable analyzers") is an aggregate over ANALYZERS, not files --
 * this collapses computeCoverageLedger's per-analyzer detail into exactly
 * that shape, counting a DISTINCT ANALYZER as being in a status if it had
 * at least one file in that status (an analyzer that failed on any file is
 * counted once under `failed`, even if it completed on every other file --
 * the point is "can this analyzer's coverage be trusted as a whole",
 * matching computeScanHealth's own binary complete/partial framing).
 */
export function summarizeCoverageForScanHealth(ledger) {
  const summary = { expected: 0, completed: 0, failed: 0, timedOut: 0, skippedByPolicy: 0 };
  for (const name of Object.keys(ledger.byAnalyzer)) {
    const a = ledger.byAnalyzer[name];
    if (a.filesExpected === 0) continue; // never applicable in this scan (e.g. no matching-extension files)
    summary.expected += 1;
    if (a.filesFailed > 0) summary.failed += 1;
    else if (a.filesTimedOut > 0) summary.timedOut += 1;
    else if (a.filesSkippedByPolicy > 0 && a.filesCompleted === 0) summary.skippedByPolicy += 1;
    else summary.completed += 1;
  }
  return summary;
}

export const _internals = { _isDisabledByPolicy };
