// Versioned, closed repair records (verified-remediation PRD section 6): NormalizedFinding, RepairContract, CandidatePatch,
// VerificationRun and the RepairRecord envelope.
//
// Built on the assurance schema kit (closed world: an unknown field is an error, never carried), with identities computed by the
// coordinator over an allowlist of semantic fields (assurance/identity.js), so no clock, run id or model-supplied count can move an id.
// Validation never throws. Migration policy: version 1.x readers accept 1.x; a 2.0 record is refused (UNSUPPORTED_MAJOR), and adding
// a field means a minor version and an allowlist entry, never a silently carried key.
import { digestOf, semanticId } from '../posture/assurance/identity.js';
import { STATE_DIR_NAME } from '../posture/state-dir.js';
import { guardObject, checkHeader, checkFields, checkEnum, checkDigest, checkString, checkCommit, result, isPlainObject, isDigest } from '../posture/assurance/schema-kit.js';

export const SCHEMAS = Object.freeze({
  finding: 'agentic-security/normalized-finding',
  contract: 'agentic-security/repair-contract',
  candidate: 'agentic-security/candidate-patch',
  run: 'agentic-security/verification-run',
  record: 'agentic-security/repair-record',
});
export const SCHEMA_VERSION = '1.0.0';

// The registered obligation kinds. A contract naming any other kind is refused: obligations are declarative and run through registered
// verifier operations only, so a contract file cannot carry an assertion of its own.
export const OBLIGATION_KINDS = Object.freeze({
  'app-attack-blocked': { oracle: 'application-security', expectBaseline: 'confirmed', expectPatched: 'refuted', set: 'development', description: 'the declared development attack requests reach no forbidden effect on the patched revision, after reproducing on the original' },
  'app-attack-sealed': { oracle: 'application-security', expectBaseline: 'confirmed', expectPatched: 'refuted', set: 'sealed', description: 'held-out attack variants, run only on a candidate that passed every development obligation; their content and outcome never reach candidate generation' },
  'app-behaviour-preserved': { oracle: 'application-behaviour', expectBaseline: 'refuted', expectPatched: 'refuted', set: 'development', description: 'the declared legitimate requests and state checks hold on the original and on the patched revision' },
  'app-behaviour-after': { oracle: 'application-behaviour', expectBaseline: null, expectPatched: 'refuted', set: 'development', description: 'legitimate requests the original mishandles (for example a quoted value) hold on the patched revision' },
  'dependency-resolved': { oracle: null, expectBaseline: 'failed', expectPatched: 'passed', set: 'development', description: 'the lockfile agrees with the manifest, every package comes from the declared sources with its recorded integrity, every dependency resolves, and no resolved instance of the advisory\'s package (direct or transitive) is in the vulnerable range' },
  'credential-removed': { oracle: null, expectBaseline: 'failed', expectPatched: 'passed', set: 'development', description: 'the leaked credential is in no application file, plain or in any re-encoding the verifier recognises (base64, hex, reversed, percent-encoded, split into joined literals, character codes)' },
  'project-tests': { oracle: null, expectBaseline: null, expectPatched: 'passed', set: 'development', description: 'the central verifier: rescan, new-finding delta, footprint and the per-test delta of the project suite' },
});

export const DISPOSITIONS = Object.freeze(['proposed', 'refuted-finding', 'needs-review', 'verified-for-contract', 'mitigation', 'rejected', 'blocked', 'cancelled']);
export const APPLICATION_STATES = Object.freeze(['not-applied', 'applied', 'reverted', 'concurrent-change-refused']);
export const ARTIFACT_STATES = Object.freeze(['unbuilt', 'source-only', 'artifact-verified', 'artifact-mismatch', 'unavailable']);
export const ENVIRONMENT_STATES = Object.freeze(['not-checked', 'staging-verified', 'deployment-observed', 'unavailable']);
export const COMPLETION_STATES = Object.freeze(['complete', 'partial', 'cancelled', 'unavailable', 'invalid']);
export const CUSTODY = Object.freeze(['internal-scan', 'imported', 'locally-corroborated', 'reproduced', 'refuted', 'unresolved']);
export const GENERATORS = Object.freeze(['deterministic-recipe', 'configured-model', 'user-supplied']);
export const FAMILIES = Object.freeze(['sql-injection', 'object-authorization', 'ssrf', 'path-traversal', 'password-storage', 'dependency', 'credential']);
export const EVIDENCE_ORIGINS = Object.freeze(['generated-from-profile', 'operator-declared', 'approved-invariant', 'counterexample', 'registered-family']);

const REL_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\w@.\-/]{1,512}$/;
export const isRelPath = (p) => typeof p === 'string' && REL_PATH.test(p) && !p.includes('\\') && p.split('/')[0] !== STATE_DIR_NAME;

// ---------------------------------------------------------------- identities (allowlisted fields only)

export const CONTRACT_ID_FIELDS = ['findingRefs', 'rootCauseGroup', 'sourceCommit', 'sourceDigest', 'configDigests', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy'];
export const contractIdOf = (c) => semanticId('rcon', c, CONTRACT_ID_FIELDS);
export const contractDigestOf = (c) => digestOf(Object.fromEntries(CONTRACT_ID_FIELDS.map((f) => [f, c[f] ?? null])));
export const CANDIDATE_ID_FIELDS = ['contractDigest', 'baselineDigest', 'patchDigest'];
export const candidateIdOf = (c) => semanticId('rcand', c, CANDIDATE_ID_FIELDS);

// ---------------------------------------------------------------- validators

export const OBLIGATION_FIELDS = ['id', 'kind', 'required', 'oracleId', 'oracleVersion', 'oracleLogicDigest', 'scope', 'baselineExpectation', 'patchedExpectation', 'evidenceOrigin', 'inputs', 'inputsDigest', 'description'];

export function validateObligation(ctx, o, i) {
  const p = `obligations[${i}]`;
  if (!isPlainObject(o)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
  for (const k of Object.keys(o)) if (!OBLIGATION_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of an obligation`);
  checkString(ctx, `${p}.id`, o.id);
  if (!Object.hasOwn(OBLIGATION_KINDS, o.kind)) { ctx.err('UNKNOWN_ENUM', `${p}.kind`, `unknown obligation kind ${JSON.stringify(o.kind)}; registered kinds: ${Object.keys(OBLIGATION_KINDS).join(', ')}`); return; }
  if (typeof o.required !== 'boolean') ctx.err('BAD_TYPE', `${p}.required`, 'must be a boolean');
  const kind = OBLIGATION_KINDS[o.kind];
  if (kind.oracle && o.oracleId !== kind.oracle) ctx.err('RULE_VIOLATION', `${p}.oracleId`, `obligation kind ${o.kind} runs only on ${kind.oracle}`);
  if (kind.oracle) checkDigest(ctx, `${p}.oracleLogicDigest`, o.oracleLogicDigest);
  if (o.inputs !== undefined) { if (!isPlainObject(o.inputs)) ctx.err('BAD_TYPE', `${p}.inputs`, 'must be an object'); else if (o.inputsDigest !== digestOf(o.inputs)) ctx.err('RULE_VIOLATION', `${p}.inputsDigest`, 'does not match the inputs'); }
  checkEnum(ctx, `${p}.evidenceOrigin`, o.evidenceOrigin, EVIDENCE_ORIGINS);
}

export const CONTRACT_FIELDS = ['schema', 'schemaVersion', 'contractId', 'contractDigest', 'family', 'findingRefs', 'rootCauseGroup', 'sourceCommit', 'sourceDigest', 'configDigests', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy', 'knownUnknowns', 'expiresAt', 'approval'];
const CONTRACT_REQUIRED = ['schema', 'schemaVersion', 'contractId', 'contractDigest', 'family', 'findingRefs', 'sourceDigest', 'profile', 'obligations', 'policyFacts', 'editScope', 'executionPolicy', 'knownUnknowns'];

export function validateContract(rec) {
  const g = guardObject(rec); if (!g.ok) return result(g.ctx);
  const ctx = g.ctx;
  if (!checkHeader(ctx, rec, SCHEMAS.contract)) return result(ctx);
  checkFields(ctx, rec, CONTRACT_FIELDS, CONTRACT_REQUIRED);
  checkEnum(ctx, 'family', rec.family, FAMILIES);
  checkCommit(ctx, 'sourceCommit', rec.sourceCommit ?? null);
  checkDigest(ctx, 'sourceDigest', rec.sourceDigest);
  if (!Array.isArray(rec.findingRefs) || !rec.findingRefs.length) ctx.err('MISSING_FIELD', 'findingRefs', 'at least one finding reference');
  if (!Array.isArray(rec.obligations) || !rec.obligations.length) ctx.err('MISSING_FIELD', 'obligations', 'at least one obligation');
  else {
    const ids = new Set();
    rec.obligations.forEach((o, i) => { validateObligation(ctx, o, i); if (ids.has(o?.id)) ctx.err('DUPLICATE_ID', `obligations[${i}].id`, 'duplicate obligation id'); ids.add(o?.id); });
    if (!rec.obligations.some((o) => o?.required)) ctx.err('RULE_VIOLATION', 'obligations', 'a contract needs at least one required obligation');
  }
  const es = rec.editScope;
  if (!isPlainObject(es) || !Array.isArray(es.allowed) || !es.allowed.every(isRelPath)) ctx.err('BAD_TYPE', 'editScope.allowed', 'must list confined relative paths');
  if (isPlainObject(es) && es.prohibited !== undefined && (!Array.isArray(es.prohibited) || !es.prohibited.every((p) => typeof p === 'string'))) ctx.err('BAD_TYPE', 'editScope.prohibited', 'must list path patterns');
  if (isPlainObject(es) && (!Number.isInteger(es.maxFiles) || es.maxFiles < 1 || es.maxFiles > 50 || !Number.isInteger(es.maxEditedLines) || es.maxEditedLines < 1 || es.maxEditedLines > 5000)) ctx.err('RULE_VIOLATION', 'editScope', 'maxFiles 1..50 and maxEditedLines 1..5000 are required');
  if (!Array.isArray(rec.policyFacts)) ctx.err('BAD_TYPE', 'policyFacts', 'must be an array');
  else rec.policyFacts.forEach((f, i) => { if (!isPlainObject(f)) return ctx.err('BAD_TYPE', `policyFacts[${i}]`, 'must be an object'); checkEnum(ctx, `policyFacts[${i}].origin`, f.origin, ['operator-profile-outside-repository', 'repository-file', 'inferred-from-code', 'approved-invariant']); checkEnum(ctx, `policyFacts[${i}].approval`, f.approval, ['approved', 'declared', 'proposed']); });
  if (!Array.isArray(rec.knownUnknowns)) ctx.err('BAD_TYPE', 'knownUnknowns', 'must be an array');
  if (rec.contractId !== undefined && rec.contractId !== contractIdOf(rec)) ctx.err('ID_MISMATCH', 'contractId', 'does not match the contract content');
  if (rec.contractDigest !== undefined && rec.contractDigest !== contractDigestOf(rec)) ctx.err('ID_MISMATCH', 'contractDigest', 'does not match the contract content');
  return result(ctx);
}

const CANDIDATE_FIELDS = ['schema', 'schemaVersion', 'candidateId', 'contractDigest', 'baselineDigest', 'generator', 'generatorIdentity', 'generationParameters', 'files', 'beforeDigests', 'afterDigests', 'patchDigest', 'scope', 'strategy', 'rationale', 'assumptions', 'proposedTests', 'accounting', 'createdAt'];

export function validateCandidate(rec) {
  const g = guardObject(rec); if (!g.ok) return result(g.ctx);
  const ctx = g.ctx;
  if (!checkHeader(ctx, rec, SCHEMAS.candidate)) return result(ctx);
  checkFields(ctx, rec, CANDIDATE_FIELDS, ['schema', 'schemaVersion', 'candidateId', 'contractDigest', 'baselineDigest', 'generator', 'generatorIdentity', 'files', 'patchDigest', 'scope', 'accounting']);
  checkEnum(ctx, 'generator', rec.generator, GENERATORS);
  checkDigest(ctx, 'contractDigest', rec.contractDigest); checkDigest(ctx, 'baselineDigest', rec.baselineDigest); checkDigest(ctx, 'patchDigest', rec.patchDigest);
  if (!isPlainObject(rec.files) || !Object.keys(rec.files).length || !Object.keys(rec.files).every(isRelPath)) ctx.err('BAD_TYPE', 'files', 'must map confined relative paths to contents');
  else for (const [k, v] of Object.entries(rec.files)) if (v !== null && typeof v !== 'string') ctx.err('BAD_TYPE', `files.${k}`, 'must be a string or null (deletion)');
  if (isPlainObject(rec.files) && rec.patchDigest !== digestOf(rec.files)) ctx.err('RULE_VIOLATION', 'patchDigest', 'does not match the files');
  const a = rec.accounting;
  if (!isPlainObject(a)) ctx.err('BAD_TYPE', 'accounting', 'must be an object');
  else for (const k of ['tokens', 'calls', 'wallMs', 'usd']) if (!(a[k] === null || (typeof a[k] === 'number' && a[k] >= 0))) ctx.err('BAD_TYPE', `accounting.${k}`, 'must be a non-negative number or null (unknown, never zero)');
  if (rec.candidateId !== undefined && rec.candidateId !== candidateIdOf(rec)) ctx.err('ID_MISMATCH', 'candidateId', 'does not match the candidate content');
  return result(ctx);
}

export const RECORD_FIELDS = ['schema', 'policyDigest', 'sourceDigest', 'patchDigest', 'exactPatch', 'schemaVersion', 'runId', 'contractId', 'contractDigest', 'findingRefs', 'disposition', 'application', 'artifact', 'environment', 'completion', 'candidates', 'selected', 'rounds', 'obligationResults', 'counterexamples', 'quarantined', 'regressionGuards', 'lifecycle', 'budget', 'accounting', 'reasons', 'nextPrerequisite', 'legacy', 'scope', 'createdAt', 'source'];

export function validateRepairRecord(rec) {
  const g = guardObject(rec); if (!g.ok) return result(g.ctx);
  const ctx = g.ctx;
  if (!checkHeader(ctx, rec, SCHEMAS.record)) return result(ctx);
  checkFields(ctx, rec, RECORD_FIELDS, ['schema', 'schemaVersion', 'runId', 'contractId', 'disposition', 'application', 'artifact', 'environment', 'completion', 'reasons', 'scope']);
  checkEnum(ctx, 'disposition', rec.disposition, DISPOSITIONS);
  checkEnum(ctx, 'application', rec.application, APPLICATION_STATES);
  checkEnum(ctx, 'artifact', rec.artifact, ARTIFACT_STATES);
  checkEnum(ctx, 'environment', rec.environment, ENVIRONMENT_STATES);
  checkEnum(ctx, 'completion', rec.completion, COMPLETION_STATES);
  // a verified-for-contract record needs a complete run with every required obligation passed
  if (rec.disposition === 'verified-for-contract') {
    if (rec.completion !== 'complete') ctx.err('RULE_VIOLATION', 'completion', 'verified-for-contract needs a complete run');
    const req = (rec.obligationResults || []).filter((o) => o.required);
    if (!req.length || req.some((o) => o.status !== 'passed')) ctx.err('RULE_VIOLATION', 'obligationResults', 'verified-for-contract needs every required obligation passed');
  }
  if (rec.artifact === 'artifact-verified' || rec.environment !== 'not-checked' && rec.environment !== 'unavailable') {
    if (!rec.source || !isDigest(rec.source.artifactDigest)) ctx.err('RULE_VIOLATION', 'artifact', 'an artifact or environment state needs a bound artifact digest');
  }
  return result(ctx);
}

/** A finding as the repair workflow sees it, from the internal scan (imported findings come through repair/importers). */
export function normalizeFinding(f, { commit = null, treeDigest = null, sourceTool = 'agentic-security', sourceToolVersion = null, custody = 'internal-scan' } = {}) {
  const loc = { file: f.file, line: Number.isInteger(f.line) ? f.line : null, column: Number.isInteger(f.column) ? f.column : null };
  return {
    schema: SCHEMAS.finding, schemaVersion: SCHEMA_VERSION,
    findingId: f.stableId || f.id, sourceTool, sourceToolVersion,
    externalRuleId: f.ruleId || f.rule || null, externalArtifactDigest: null,
    repository: { commit, treeDigest },
    locations: [loc], cwe: f.cwe || null, family: f.family || null, vuln: f.vuln || null,
    severity: f.severity || null, confidence: f.confidence ?? null, reachability: f.relevanceTier || f.reachability || null,
    exploitEvidence: f.proofTier || null, disposition: 'open', custody,
    mappingLimitations: f.cwe ? [] : ['no CWE was reported; it is unknown, not inferred'],
  };
}
