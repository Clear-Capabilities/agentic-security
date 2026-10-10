// Release assurance manifest (X-701).
//
// A manifest binds one release claim to the exact identities it is about, and says out loud what was NOT checked. It is a
// closed-world record built on the assurance schema kit (assurance/schema-kit.js) and the deterministic identity helpers
// (assurance/identity.js), the same pair the release-evidence contract uses, so a manifest id is a refactor-stable hash over an
// allowlist of semantic fields and never covers a clock.
//
// What it binds (X-701.AC01): the subject repository and commit, every dependency revision, every build artifact digest, the scan
// scope, the graph snapshot digest, the invariant versions and the verification receipts the claim rests on.
//
// What it discloses (X-701.AC02): every mandatory check lands in exactly one of completed / incomplete / unsupported / waived, and
// the exact blocking-finding policy (id, digest, minimum blocking severity) is part of the record. A waiver names who approved it and
// why; an incomplete or unsupported check names what is missing.
//
// What validation REFUSES (X-701.AC03): evidence that is not bound to a declared receipt, a receipt whose commit is not the commit of
// the repository it claims to be about, a mandatory check that appears nowhere, and a coverage block that disagrees with the check
// lists. Residual risks and coverage are preserved as machine-readable fields, never folded into prose.
//
// Pure: no fs, no clock, no network. Synthetic fixtures set `synthetic: true`; that flag is carried, never inferred.

import {
  SCHEMA_VERSION, isPlainObject, isDigest, checkHeader, checkFields, checkDigest, checkCommit, checkString, checkEnum, checkId, result, guardObject,
} from '../assurance/schema-kit.js';
import { semanticId, digestOf } from '../assurance/identity.js';

export const MANIFEST_SCHEMA = 'agentic-security/release-assurance-manifest';
const MANIFEST_ID_PREFIX = 'ram';
const BLOCKING_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low']);
const CHECK_GROUPS = Object.freeze(['completed', 'incomplete', 'unsupported', 'waived']);

// Hard ceilings: a manifest is attacker-influenced input at verify time.
const MANIFEST_LIMITS = Object.freeze({ maxChecks: 512, maxReceipts: 2048, maxArtifacts: 512, maxDependencies: 512, maxInvariants: 512, maxRisks: 256 });

const ALLOWED = [
  'schema', 'schemaVersion', 'id', 'synthetic', 'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions',
  'verificationReceipts', 'checks', 'policy', 'findings', 'residualRisks', 'coverage', 'complete', 'createdAt',
];
const REQUIRED = [
  'schema', 'schemaVersion', 'id', 'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions',
  'verificationReceipts', 'checks', 'policy', 'findings', 'residualRisks', 'coverage', 'complete',
];
const ID_FIELDS = Object.freeze([
  'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions', 'verificationReceipts', 'checks', 'policy',
  'findings', 'residualRisks', 'coverage', 'complete',
]);

export const manifestId = (m) => semanticId(MANIFEST_ID_PREFIX, m, ID_FIELDS);
/** The digest a signature binds: the whole manifest, key-order independent. */
export const manifestDigest = (m) => digestOf(m);

/** Counts derived from the check lists. The stored `coverage` must equal this, so it cannot drift from the lists it summarizes. */
export function deriveCoverage(checks, scope) {
  const n = (g) => (Array.isArray(checks?.[g]) ? checks[g].length : 0);
  const mandatory = Array.isArray(scope?.mandatory) ? scope.mandatory.length : 0;
  return {
    mandatory, completed: n('completed'), incomplete: n('incomplete'), unsupported: n('unsupported'), waived: n('waived'),
    complete: mandatory > 0 && n('incomplete') === 0 && n('unsupported') === 0 && n('completed') + n('waived') === mandatory,
  };
}

/** Build a manifest from the bound facts; coverage, completeness and id are computed, never supplied. */
export function buildManifest(f) {
  const checks = {
    completed: f.checks?.completed ?? [], incomplete: f.checks?.incomplete ?? [], unsupported: f.checks?.unsupported ?? [], waived: f.checks?.waived ?? [],
  };
  const m = {
    schema: MANIFEST_SCHEMA, schemaVersion: SCHEMA_VERSION,
    ...(f.synthetic === true ? { synthetic: true } : {}),
    subject: f.subject, dependencies: f.dependencies ?? [], artifacts: f.artifacts ?? [], scope: f.scope,
    graphSnapshot: f.graphSnapshot, invariantVersions: f.invariantVersions ?? [], verificationReceipts: f.verificationReceipts ?? [],
    checks, policy: f.policy, findings: f.findings, residualRisks: f.residualRisks ?? [],
    coverage: deriveCoverage(checks, f.scope),
  };
  m.complete = m.coverage.complete;
  m.id = manifestId(m);
  return m;
}

function checkList(ctx, p, list, max) {
  if (!Array.isArray(list)) { ctx.err('BAD_TYPE', p, 'must be an array'); return false; }
  if (list.length > max) { ctx.err('RULE_VIOLATION', p, `has ${list.length} entries; the limit is ${max}`); return false; }
  return true;
}

function closedKeys(ctx, p, obj, allowed, what) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `not part of ${what}`);
}

function isCommitLike(v) { return typeof v === 'string' && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(v); }

export function validateManifest(m) {
  const g = guardObject(m);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, m, MANIFEST_SCHEMA)) return result(ctx);
  checkFields(ctx, m, ALLOWED, REQUIRED);
  if (m.synthetic !== undefined && m.synthetic !== true) ctx.err('BAD_TYPE', 'synthetic', 'must be true when present');

  // subject
  const s = m.subject;
  const repoCommits = new Map();
  if (!isPlainObject(s)) ctx.err('BAD_TYPE', 'subject', 'must be an object');
  else {
    closedKeys(ctx, 'subject', s, ['repository', 'commit', 'bundleDigest', 'policyDigest'], 'subject');
    checkString(ctx, 'subject.repository', s.repository);
    checkCommit(ctx, 'subject.commit', s.commit ?? null, { nullable: false });
    checkDigest(ctx, 'subject.bundleDigest', s.bundleDigest ?? null);
    checkDigest(ctx, 'subject.policyDigest', s.policyDigest ?? null);
    if (typeof s.repository === 'string') repoCommits.set(s.repository, s.commit);
  }

  // dependencies
  if (checkList(ctx, 'dependencies', m.dependencies, MANIFEST_LIMITS.maxDependencies)) {
    m.dependencies.forEach((d, i) => {
      const p = `dependencies[${i}]`;
      if (!isPlainObject(d)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
      closedKeys(ctx, p, d, ['name', 'revision'], 'a dependency');
      if (checkString(ctx, `${p}.name`, d.name)) {
        if (repoCommits.has(d.name)) ctx.err('DUPLICATE_ID', `${p}.name`, `dependency '${d.name}' is declared twice or collides with the subject repository`);
        else repoCommits.set(d.name, d.revision);
      }
      checkString(ctx, `${p}.revision`, d.revision);
    });
  }

  // artifacts
  if (checkList(ctx, 'artifacts', m.artifacts, MANIFEST_LIMITS.maxArtifacts)) {
    if (m.artifacts.length === 0) ctx.err('RULE_VIOLATION', 'artifacts', 'a release manifest must bind at least one build artifact digest');
    m.artifacts.forEach((a, i) => {
      const p = `artifacts[${i}]`;
      if (!isPlainObject(a)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
      closedKeys(ctx, p, a, ['name', 'digest'], 'an artifact');
      checkString(ctx, `${p}.name`, a.name);
      checkDigest(ctx, `${p}.digest`, a.digest);
    });
  }

  // scope
  const mandatory = new Set();
  if (!isPlainObject(m.scope)) ctx.err('BAD_TYPE', 'scope', 'must be an object');
  else {
    closedKeys(ctx, 'scope', m.scope, ['description', 'mandatory'], 'scope');
    checkString(ctx, 'scope.description', m.scope.description);
    if (checkList(ctx, 'scope.mandatory', m.scope.mandatory, MANIFEST_LIMITS.maxChecks)) {
      if (m.scope.mandatory.length === 0) ctx.err('RULE_VIOLATION', 'scope.mandatory', 'a manifest must name at least one mandatory check');
      m.scope.mandatory.forEach((id, i) => {
        if (!checkString(ctx, `scope.mandatory[${i}]`, id)) return;
        if (mandatory.has(id)) ctx.err('DUPLICATE_ID', `scope.mandatory[${i}]`, `duplicate mandatory check '${id}'`);
        mandatory.add(id);
      });
    }
  }

  // graph snapshot
  if (!isPlainObject(m.graphSnapshot)) ctx.err('BAD_TYPE', 'graphSnapshot', 'must be an object');
  else {
    closedKeys(ctx, 'graphSnapshot', m.graphSnapshot, ['digest'], 'graphSnapshot');
    checkDigest(ctx, 'graphSnapshot.digest', m.graphSnapshot.digest ?? null);
  }

  if (checkList(ctx, 'invariantVersions', m.invariantVersions, MANIFEST_LIMITS.maxInvariants)) {
    m.invariantVersions.forEach((v, i) => {
      const p = `invariantVersions[${i}]`;
      if (!isPlainObject(v)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
      closedKeys(ctx, p, v, ['id', 'version'], 'an invariant version');
      checkString(ctx, `${p}.id`, v.id); checkString(ctx, `${p}.version`, v.version);
    });
  }

  // receipts: each must be about a declared repository and carry THAT repository's commit
  const receipts = new Map();
  if (checkList(ctx, 'verificationReceipts', m.verificationReceipts, MANIFEST_LIMITS.maxReceipts)) {
    m.verificationReceipts.forEach((r, i) => {
      const p = `verificationReceipts[${i}]`;
      if (!isPlainObject(r)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
      closedKeys(ctx, p, r, ['id', 'digest', 'repository', 'commit'], 'a receipt');
      if (checkString(ctx, `${p}.id`, r.id)) {
        if (receipts.has(r.id)) ctx.err('DUPLICATE_ID', `${p}.id`, `duplicate receipt '${r.id}'`);
        receipts.set(r.id, r);
      }
      checkDigest(ctx, `${p}.digest`, r.digest);
      checkCommit(ctx, `${p}.commit`, r.commit ?? null, { nullable: false });
      if (checkString(ctx, `${p}.repository`, r.repository)) {
        if (!repoCommits.has(r.repository)) ctx.err('DANGLING_REF', `${p}.repository`, `receipt is about '${r.repository}', which is neither the subject repository nor a declared dependency`);
        else if (isCommitLike(repoCommits.get(r.repository)) && r.commit !== repoCommits.get(r.repository)) {
          ctx.err('RULE_VIOLATION', `${p}.commit`, `commit mismatch: receipt commit ${String(r.commit).slice(0, 12)} is not the bound commit ${String(repoCommits.get(r.repository)).slice(0, 12)} of '${r.repository}'`);
        }
      }
    });
  }

  // checks
  const seenIds = new Map();
  if (!isPlainObject(m.checks)) ctx.err('BAD_TYPE', 'checks', 'must be an object');
  else {
    closedKeys(ctx, 'checks', m.checks, CHECK_GROUPS, 'a check group');
    for (const grp of CHECK_GROUPS) {
      if (!checkList(ctx, `checks.${grp}`, m.checks[grp], MANIFEST_LIMITS.maxChecks)) continue;
      m.checks[grp].forEach((c, i) => {
        const p = `checks.${grp}[${i}]`;
        if (!isPlainObject(c)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
        closedKeys(ctx, p, c, ['id', 'statement', 'evidenceRefs', 'gaps', 'reason', 'approvedBy'], 'a check');
        if (checkString(ctx, `${p}.id`, c.id)) {
          if (seenIds.has(c.id)) ctx.err('DUPLICATE_ID', `${p}.id`, `check '${c.id}' is already listed under ${seenIds.get(c.id)}`);
          else seenIds.set(c.id, grp);
          if (mandatory.size && !mandatory.has(c.id)) ctx.err('RULE_VIOLATION', `${p}.id`, `check '${c.id}' is not part of the declared mandatory scope`);
        }
        checkString(ctx, `${p}.statement`, c.statement);
        const refs = c.evidenceRefs;
        if (!Array.isArray(refs) || !refs.every((x) => typeof x === 'string')) ctx.err('BAD_TYPE', `${p}.evidenceRefs`, 'must be an array of receipt ids');
        else {
          if (grp === 'completed' && refs.length === 0) ctx.err('RULE_VIOLATION', `${p}.evidenceRefs`, 'a completed check must cite evidence');
          refs.forEach((ref, j) => { if (!receipts.has(ref)) ctx.err('DANGLING_REF', `${p}.evidenceRefs[${j}]`, `unbound evidence: '${ref}' is not a declared verification receipt`); });
        }
        const gapsOk = Array.isArray(c.gaps) && c.gaps.every((x) => typeof x === 'string' && x.trim());
        if (grp === 'incomplete' || grp === 'unsupported') {
          if (!gapsOk || c.gaps.length === 0) ctx.err('RULE_VIOLATION', `${p}.gaps`, `a ${grp} check must say what is missing`);
        } else if (c.gaps !== undefined && (!gapsOk || c.gaps.length > 0)) ctx.err('RULE_VIOLATION', `${p}.gaps`, `a ${grp} check cannot list gaps`);
        if (grp === 'waived') { checkString(ctx, `${p}.reason`, c.reason); checkString(ctx, `${p}.approvedBy`, c.approvedBy); }
      });
    }
    for (const id of mandatory) if (!seenIds.has(id)) ctx.err('RULE_VIOLATION', 'checks', `omitted mandatory scope: '${id}' is not completed, incomplete, unsupported or waived`);
  }

  // policy
  if (!isPlainObject(m.policy)) ctx.err('BAD_TYPE', 'policy', 'must be an object');
  else {
    closedKeys(ctx, 'policy', m.policy, ['id', 'digest', 'blockingSeverity'], 'policy');
    checkString(ctx, 'policy.id', m.policy.id);
    checkDigest(ctx, 'policy.digest', m.policy.digest);
    checkEnum(ctx, 'policy.blockingSeverity', m.policy.blockingSeverity, BLOCKING_SEVERITIES);
    if (isPlainObject(s) && isDigest(m.policy.digest) && m.policy.digest !== s.policyDigest) ctx.err('RULE_VIOLATION', 'policy.digest', 'policy digest does not match subject.policyDigest');
  }

  // findings summary
  if (!isPlainObject(m.findings)) ctx.err('BAD_TYPE', 'findings', 'must be an object');
  else {
    closedKeys(ctx, 'findings', m.findings, ['total', 'blocking'], 'findings');
    for (const k of ['total', 'blocking']) if (!Number.isInteger(m.findings[k]) || m.findings[k] < 0) ctx.err('BAD_TYPE', `findings.${k}`, 'must be a non-negative integer');
    if (Number.isInteger(m.findings.total) && Number.isInteger(m.findings.blocking) && m.findings.blocking > m.findings.total) ctx.err('RULE_VIOLATION', 'findings.blocking', 'blocking cannot exceed total');
  }

  // residual risks
  if (checkList(ctx, 'residualRisks', m.residualRisks, MANIFEST_LIMITS.maxRisks)) {
    m.residualRisks.forEach((r, i) => {
      const p = `residualRisks[${i}]`;
      if (!isPlainObject(r)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
      closedKeys(ctx, p, r, ['id', 'statement', 'severity'], 'a residual risk');
      checkString(ctx, `${p}.id`, r.id); checkString(ctx, `${p}.statement`, r.statement);
      checkEnum(ctx, `${p}.severity`, r.severity, [...BLOCKING_SEVERITIES, 'info']);
    });
  }

  // coverage and completeness must agree with the lists
  if (isPlainObject(m.checks) && isPlainObject(m.scope)) {
    const want = deriveCoverage(m.checks, m.scope);
    if (!isPlainObject(m.coverage) || digestOf(m.coverage) !== digestOf(want)) ctx.err('RULE_VIOLATION', 'coverage', `coverage disagrees with the check lists (expected ${JSON.stringify(want)})`);
    if (typeof m.complete !== 'boolean') ctx.err('BAD_TYPE', 'complete', 'must be a boolean');
    else if (m.complete !== want.complete) ctx.err('RULE_VIOLATION', 'complete', `claimed complete=${m.complete} but the check lists support complete=${want.complete}`);
  }
  checkId(ctx, m, manifestId(m));
  return result(ctx);
}
