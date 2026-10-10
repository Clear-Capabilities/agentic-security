export const id = 7439;
export const ids = [7439];
export const modules = {

/***/ 33889:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  mt: () => (/* binding */ findSecret)
});

// UNUSED EXPORTS: BLOB_DIR, BUNDLE_LIMITS, BUNDLE_SCHEMA, INDEX_FILE, ROLES, bundleDigestOf, checkLogicalName, exportBundle, importBundle, verifyBundle

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/evidence-bundle.js
var evidence_bundle = __webpack_require__(98317);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/llm-validator/redact.js
var redact = __webpack_require__(65388);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
;// CONCATENATED MODULE: ./src/posture/portfolio/manifest.js
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




const MANIFEST_SCHEMA = 'agentic-security/release-assurance-manifest';
const MANIFEST_ID_PREFIX = 'ram';
const BLOCKING_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low']);
const CHECK_GROUPS = Object.freeze(['completed', 'incomplete', 'unsupported', 'waived']);

// Hard ceilings: a manifest is attacker-influenced input at verify time.
const MANIFEST_LIMITS = Object.freeze({ maxChecks: 512, maxReceipts: 2048, maxArtifacts: 512, maxDependencies: 512, maxInvariants: 512, maxRisks: 256 });

const ALLOWED = (/* unused pure expression or super */ null && ([
  'schema', 'schemaVersion', 'id', 'synthetic', 'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions',
  'verificationReceipts', 'checks', 'policy', 'findings', 'residualRisks', 'coverage', 'complete', 'createdAt',
]));
const REQUIRED = (/* unused pure expression or super */ null && ([
  'schema', 'schemaVersion', 'id', 'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions',
  'verificationReceipts', 'checks', 'policy', 'findings', 'residualRisks', 'coverage', 'complete',
]));
const ID_FIELDS = Object.freeze([
  'subject', 'dependencies', 'artifacts', 'scope', 'graphSnapshot', 'invariantVersions', 'verificationReceipts', 'checks', 'policy',
  'findings', 'residualRisks', 'coverage', 'complete',
]);

const manifestId = (m) => semanticId(MANIFEST_ID_PREFIX, m, ID_FIELDS);
/** The digest a signature binds: the whole manifest, key-order independent. */
const manifest_manifestDigest = (m) => digestOf(m);

/** Counts derived from the check lists. The stored `coverage` must equal this, so it cannot drift from the lists it summarizes. */
function deriveCoverage(checks, scope) {
  const n = (g) => (Array.isArray(checks?.[g]) ? checks[g].length : 0);
  const mandatory = Array.isArray(scope?.mandatory) ? scope.mandatory.length : 0;
  return {
    mandatory, completed: n('completed'), incomplete: n('incomplete'), unsupported: n('unsupported'), waived: n('waived'),
    complete: mandatory > 0 && n('incomplete') === 0 && n('unsupported') === 0 && n('completed') + n('waived') === mandatory,
  };
}

/** Build a manifest from the bound facts; coverage, completeness and id are computed, never supplied. */
function buildManifest(f) {
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

function manifest_validateManifest(m) {
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

;// CONCATENATED MODULE: ./src/posture/portfolio/bundle.js
// Portable, content-addressed evidence bundle and its OFFLINE verifier (X-702).
//
// A bundle is a directory:
//
//     bundle.json        the index: schema, manifest digest, every entry (role, logical name, digest, size), replay prerequisites
//     blobs/<sha256 hex> one file per entry, named by the digest of its canonical bytes
//
// Everything a reviewer needs to check a release claim is in it (X-702.AC01): the assurance manifest, the SANITIZED findings, finding
// provenance, replay manifests, the dependency and toolchain identities, and the verification receipts the manifest cites. Nothing in it
// refers to the agent conversation that produced the work.
//
// The verifier (X-702.AC02) uses node:fs and node:crypto only. It never opens a socket and never executes anything from the bundle:
// it re-hashes every blob against the index, validates the manifest through manifest.js, checks that every receipt the manifest cites
// is present as a blob, and then DISCLOSES what a runtime replay would need (`replay.prerequisites`) without attempting one. A verified
// bundle therefore proves its contents are unmodified; it does not prove a replay would still reproduce today.
//
// Export and import enforce limits (X-702.AC03): entry count, per-blob and total bytes, logical-name shape (no absolute path, no `..`,
// no unusual characters), no symlinks, and a secret filter. The filter first REDACTS known secret shapes in findings and provenance, then
// refuses to write a blob in which any secret shape survives; the importer refuses a bundle that carries one. A missing blob, a modified
// blob or a modified index fails integrity validation; none is ever repaired or skipped silently.








const BUNDLE_SCHEMA = 'agentic-security/portable-evidence-bundle';
const BUNDLE_VERSION = '1.0.0';
const INDEX_FILE = 'bundle.json';
const BLOB_DIR = 'blobs';
const ROLES = Object.freeze(['manifest', 'findings', 'provenance', 'replay-manifest', 'toolchain', 'receipt']);
const REQUIRED_ROLES = Object.freeze(['manifest', 'findings', 'provenance', 'toolchain']);

const BUNDLE_LIMITS = Object.freeze({ maxEntries: 4096, maxBlobBytes: 4 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024, maxIndexBytes: 8 * 1024 * 1024, maxNameLength: 200, maxDepth: 24, maxString: 8192 });

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

// ---------------------------------------------------------------- secret filter

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']?[^\s"',;]{8,}/i,
];
const PLACEHOLDER = '[REDACTED-SECRET]';

/** The first secret shape found in a text, or null. */
function findSecret(text) {
  if (typeof text !== 'string') return null;
  for (const re of SECRET_PATTERNS) { const m = re.exec(text); if (m && !m[0].includes(PLACEHOLDER)) return m[0].slice(0, 12) + '...'; }
  return null;
}

/** Replace every known secret shape with a placeholder. */
function redactText(text) {
  let out = String(text);
  for (const re of SECRET_PATTERNS) out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'), PLACEHOLDER);
  return redactSecrets(out).text;
}

function sanitizeValue(v, depth = 0) {
  if (depth > BUNDLE_LIMITS.maxDepth) throw new Error('evidence is nested deeper than the limit');
  if (typeof v === 'string') return redactText(v.length > BUNDLE_LIMITS.maxString ? v.slice(0, BUNDLE_LIMITS.maxString) : v);
  if (Array.isArray(v)) return v.map((x) => sanitizeValue(x, depth + 1));
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sanitizeValue(v[k], depth + 1)]));
  return v;
}

// A finding leaves the machine as a closed set of fields. Source snippets, taint traces and raw evidence stay behind.
const FINDING_FIELDS = (/* unused pure expression or super */ null && (['id', 'stableId', 'severity', 'file', 'line', 'vuln', 'cwe', 'family', 'parser', 'confidence', 'confidenceTier', 'description', 'remediation', 'unreachable', 'findingProvenance']));

function sanitizeFindings(findings) {
  return (Array.isArray(findings) ? findings : []).map((f) => {
    const out = {};
    for (const k of FINDING_FIELDS) if (f && f[k] !== undefined) out[k] = sanitizeValue(f[k]);
    return out;
  });
}

// ---------------------------------------------------------------- names and paths

function checkLogicalName(name) {
  if (typeof name !== 'string' || !name) return 'empty name';
  if (name.length > BUNDLE_LIMITS.maxNameLength) return `name longer than ${BUNDLE_LIMITS.maxNameLength}`;
  if (name.includes('\0') || name.includes('\\')) return 'name contains a NUL or backslash';
  if (path.isAbsolute(name) || name.startsWith('/')) return 'absolute path';
  if (name.split('/').some((s) => s === '..' || s === '.')) return 'path traversal';
  if (!NAME_RE.test(name)) return 'name has characters outside the allowed set';
  return null;
}

function blobFile(dir, digest) { return path.join(dir, BLOB_DIR, digest.slice('sha256:'.length)); }

function writeAtomic(file, bytes) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, bytes, { flag: 'wx', mode: 0o644 });
  fs.renameSync(tmp, file);
}

// ---------------------------------------------------------------- replay prerequisites

const BASE_PREREQUISITES = Object.freeze([
  { code: 'source-at-commit', statement: 'the exact source revision named by the manifest subject must be checked out' },
  { code: 'toolchain-identities', statement: 'the toolchain identities recorded in the bundle must be installed at the recorded versions' },
  { code: 'confinement-backend', statement: 'a runtime replay needs a confinement backend; isolation-required replays are only advertised on Linux and enforcement there is unverified in this build' },
]);

function replayPrerequisites(replayManifests) {
  const seen = new Set(BASE_PREREQUISITES.map((p) => p.code));
  const out = BASE_PREREQUISITES.map((p) => ({ ...p }));
  for (const rm of replayManifests) {
    for (const p of Array.isArray(rm?.prerequisites) ? rm.prerequisites : []) {
      const code = typeof p === 'string' ? p : p?.code;
      if (typeof code !== 'string' || seen.has(code)) continue;
      seen.add(code);
      out.push({ code, statement: typeof p === 'object' && typeof p.statement === 'string' ? p.statement : code, source: rm.id ?? null });
    }
  }
  return out;
}

// ---------------------------------------------------------------- export

/**
 * Write a bundle to `outDir` (must not exist or must be empty). Throws on a limit, name, manifest or secret violation, and writes the
 * index LAST so a half-written directory has no index and never verifies.
 *
 * @param {object} a
 * @param {object} a.manifest        a valid release assurance manifest
 * @param {object[]} a.findings      raw findings; sanitized here
 * @param {object} a.provenance      finding provenance and dependency identities
 * @param {object[]} [a.replayManifests]  `{ id, prerequisites?, ... }`
 * @param {object} a.toolchain       toolchain identities
 * @param {Array<{id:string, content:*}>} [a.receipts]  the verification receipt contents; each digest must equal the manifest's
 */
function exportBundle({ outDir, manifest, findings = [], provenance = {}, replayManifests = [], toolchain = {}, receipts = [] }) {
  const v = validateManifest(manifest);
  if (!v.ok) throw new Error(`refusing to export: the manifest is invalid (${v.errors[0].code} ${v.errors[0].path})`);
  if (fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0) throw new Error('refusing to export into a non-empty directory');

  const items = [];
  const add = (role, name, value, sanitize = true) => {
    const bad = checkLogicalName(name);
    if (bad) throw new Error(`refusing to export '${name}': ${bad}`);
    const body = sanitize ? sanitizeValue(value) : value;
    const bytes = Buffer.from(canonicalJson(body));
    if (bytes.length > BUNDLE_LIMITS.maxBlobBytes) throw new Error(`refusing to export '${name}': ${bytes.length} bytes exceeds the ${BUNDLE_LIMITS.maxBlobBytes} byte limit`);
    const hit = findSecret(bytes.toString('utf8'));
    if (hit) throw new Error(`refusing to export '${name}': a secret shape survived redaction (${hit})`);
    items.push({ role, name, digest: digestOfBytes(bytes), size: bytes.length, bytes });
  };
  add('manifest', 'manifest.json', manifest, false);
  add('findings', 'findings.json', sanitizeFindings(findings), false);
  add('provenance', 'provenance.json', provenance);
  add('toolchain', 'toolchain.json', toolchain);
  replayManifests.forEach((rm, i) => add('replay-manifest', `replay/${String(rm?.id ?? i).replace(/[^A-Za-z0-9._-]/g, '_')}.json`, rm));
  const byId = new Map(receipts.map((r) => [r.id, r]));
  for (const r of manifest.verificationReceipts) {
    const given = byId.get(r.id);
    if (!given) throw new Error(`refusing to export: receipt '${r.id}' cited by the manifest was not supplied`);
    if (digestOf(given.content) !== r.digest) throw new Error(`refusing to export: receipt '${r.id}' content does not match the digest the manifest binds`);
    add('receipt', `receipts/${r.id.replace(/[^A-Za-z0-9._-]/g, '_')}.json`, given.content);
  }
  if (items.length > BUNDLE_LIMITS.maxEntries) throw new Error('refusing to export: too many entries');
  const total = items.reduce((n, i) => n + i.size, 0);
  if (total > BUNDLE_LIMITS.maxTotalBytes) throw new Error('refusing to export: total size exceeds the limit');
  const names = new Set();
  for (const i of items) { if (names.has(i.name)) throw new Error(`refusing to export: duplicate name '${i.name}'`); names.add(i.name); }

  fs.mkdirSync(path.join(outDir, BLOB_DIR), { recursive: true });
  for (const i of items) {
    const f = blobFile(outDir, i.digest);
    if (!fs.existsSync(f)) writeAtomic(f, i.bytes);
  }
  const entries = items.map(({ role, name, digest, size }) => ({ role, name, digest, size })).sort((a, b) => (a.name < b.name ? -1 : 1));
  const index = indexFor(entries, manifest, replayManifests);
  writeAtomic(path.join(outDir, INDEX_FILE), Buffer.from(JSON.stringify(index, null, 2)));
  return { bundleDigest: index.bundleDigest, manifestDigest: index.manifestDigest, entries: entries.length, totalBytes: total };
}

function indexFor(entries, manifest, replayManifests) {
  const body = {
    schema: BUNDLE_SCHEMA, schemaVersion: BUNDLE_VERSION,
    ...(manifest.synthetic === true ? { synthetic: true } : {}),
    manifestId: manifest.id, manifestDigest: manifestDigest(manifest), entries,
    replay: { attempted: false, prerequisites: replayPrerequisites(replayManifests) },
    limits: BUNDLE_LIMITS,
  };
  return { ...body, bundleDigest: bundleDigestOf(body) };
}

/** The identity of a bundle: the manifest digest plus every entry's digest, independent of file order. */
function bundleDigestOf(index) {
  return digestOf({ manifestDigest: index.manifestDigest, entries: index.entries.map((e) => [e.role, e.name, e.digest, e.size]) });
}

// ---------------------------------------------------------------- verify (offline)

function readBounded(file, max) {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile()) throw Object.assign(new Error('not a regular file'), { code: 'NOT_REGULAR' });
  if (st.size > max) throw Object.assign(new Error(`${st.size} bytes exceeds ${max}`), { code: 'TOO_LARGE' });
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(Math.min(st.size, max) + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    if (n > max) throw Object.assign(new Error('grew past the limit while reading'), { code: 'TOO_LARGE' });
    return buf.subarray(0, n);
  } finally { fs.closeSync(fd); }
}

/**
 * Verify a bundle directory using only the local filesystem. Returns `{ ok, errors, manifest, entries, replay, network:false }`.
 * `errors` carry a stable `code`: BAD_INDEX, BAD_ENTRY, MISSING_BLOB, DIGEST_MISMATCH, SIZE_MISMATCH, TOO_LARGE, NOT_REGULAR,
 * BUNDLE_DIGEST_MISMATCH, MANIFEST_INVALID, MANIFEST_MISMATCH, MISSING_EVIDENCE, MISSING_ROLE, SECRET_IN_BLOB, LIMIT.
 */
function verifyBundle(dir) {
  const errors = [];
  const err = (code, message, extra = {}) => errors.push({ code, message, ...extra });
  const out = (extra = {}) => ({ ok: errors.length === 0, errors, network: false, manifest: null, entries: [], replay: { attempted: false, prerequisites: [], statement: 'replay was not attempted: this verifier is offline and executes nothing from the bundle' }, ...extra });

  let index;
  try { index = JSON.parse(readBounded(path.join(dir, INDEX_FILE), BUNDLE_LIMITS.maxIndexBytes).toString('utf8')); } catch (e) {
    err('BAD_INDEX', `cannot read ${INDEX_FILE}: ${e.code || e.message}`); return out();
  }
  if (!index || index.schema !== BUNDLE_SCHEMA || !Array.isArray(index.entries) || typeof index.bundleDigest !== 'string') { err('BAD_INDEX', 'not a portable evidence bundle index'); return out(); }
  if (index.entries.length > BUNDLE_LIMITS.maxEntries) { err('LIMIT', 'too many entries'); return out(); }

  const names = new Set();
  let total = 0;
  const loaded = new Map();
  for (const e of index.entries) {
    if (!e || !ROLES.includes(e.role) || !DIGEST_RE.test(e.digest ?? '') || !Number.isInteger(e.size) || e.size < 0) { err('BAD_ENTRY', 'malformed entry', { entry: e?.name ?? null }); continue; }
    const bad = checkLogicalName(e.name);
    if (bad) { err('BAD_ENTRY', `entry name rejected: ${bad}`, { entry: String(e.name).slice(0, 60) }); continue; }
    if (names.has(e.name)) { err('BAD_ENTRY', 'duplicate entry name', { entry: e.name }); continue; }
    names.add(e.name);
    if (e.size > BUNDLE_LIMITS.maxBlobBytes) { err('TOO_LARGE', `entry exceeds the per-blob limit`, { entry: e.name }); continue; }
    total += e.size;
    let bytes;
    try { bytes = readBounded(blobFile(dir, e.digest), BUNDLE_LIMITS.maxBlobBytes); } catch (x) {
      err(x.code === 'ENOENT' ? 'MISSING_BLOB' : (x.code || 'MISSING_BLOB'), `blob for '${e.name}' is unavailable: ${x.code || x.message}`, { entry: e.name }); continue;
    }
    if (bytes.length !== e.size) { err('SIZE_MISMATCH', `blob size differs from the index`, { entry: e.name }); continue; }
    if (digestOfBytes(bytes) !== e.digest) { err('DIGEST_MISMATCH', `blob for '${e.name}' was modified after export`, { entry: e.name }); continue; }
    const hit = findSecret(bytes.toString('utf8'));
    if (hit) err('SECRET_IN_BLOB', `'${e.name}' carries a secret shape`, { entry: e.name });
    loaded.set(e.name, { e, bytes });
  }
  if (total > BUNDLE_LIMITS.maxTotalBytes) err('LIMIT', 'total size exceeds the limit');
  for (const role of REQUIRED_ROLES) if (!index.entries.some((e) => e?.role === role)) err('MISSING_ROLE', `required role '${role}' is absent`);
  if (index.entries.every((e) => e && DIGEST_RE.test(e.digest ?? '')) && bundleDigestOf(index) !== index.bundleDigest) err('BUNDLE_DIGEST_MISMATCH', 'the index does not match its recorded bundle digest');

  // manifest
  let manifest = null;
  const mEntry = index.entries.find((e) => e?.role === 'manifest');
  if (mEntry && loaded.has(mEntry.name)) {
    try { manifest = JSON.parse(loaded.get(mEntry.name).bytes.toString('utf8')); } catch { err('MANIFEST_INVALID', 'manifest is not JSON'); }
    if (manifest) {
      const v = validateManifest(manifest);
      if (!v.ok) err('MANIFEST_INVALID', `manifest fails validation: ${v.errors[0].code} ${v.errors[0].path}`, { detail: v.errors.slice(0, 5) });
      else {
        if (manifestDigest(manifest) !== index.manifestDigest) err('MANIFEST_MISMATCH', 'the manifest is not the one the index was built for');
        const have = new Set(index.entries.filter((e) => e?.role === 'receipt').map((e) => e.digest));
        for (const r of manifest.verificationReceipts) if (!have.has(r.digest)) err('MISSING_EVIDENCE', `receipt '${r.id}' cited by the manifest is not in the bundle`, { receipt: r.id });
      }
    }
  }
  const replayManifests = [];
  for (const [, { e, bytes }] of loaded) if (e.role === 'replay-manifest') { try { replayManifests.push(JSON.parse(bytes.toString('utf8'))); } catch { /* integrity already checked; unparsable replay manifest adds no prerequisites */ } }
  return out({
    manifest: errors.length === 0 ? manifest : null,
    entries: [...loaded.values()].map(({ e }) => ({ role: e.role, name: e.name, digest: e.digest })),
    bundleDigest: index.bundleDigest,
    replay: { attempted: false, prerequisites: replayPrerequisites(replayManifests), statement: 'replay was not attempted: this verifier is offline and executes nothing from the bundle' },
  });
}

// ---------------------------------------------------------------- import

/**
 * Verify `from`, then materialize its entries under `to` using their logical names. Verification failure writes nothing. Every
 * destination is resolved and confined to `to`; an existing destination is never overwritten.
 */
function importBundle({ from, to }) {
  const v = verifyBundle(from);
  if (!v.ok) return { ok: false, errors: v.errors, written: [] };
  const index = JSON.parse(fs.readFileSync(path.join(from, INDEX_FILE), 'utf8'));
  const root = path.resolve(to);
  const plan = [];
  for (const e of index.entries) {
    const dest = path.resolve(root, e.name);
    if (dest !== root && !dest.startsWith(root + path.sep)) return { ok: false, errors: [{ code: 'BAD_ENTRY', message: `entry '${e.name}' escapes the destination` }], written: [] };
    if (fs.existsSync(dest)) return { ok: false, errors: [{ code: 'DESTINATION_EXISTS', message: `'${e.name}' already exists at the destination` }], written: [] };
    plan.push({ e, dest });
  }
  fs.mkdirSync(root, { recursive: true });
  const written = [];
  for (const { e, dest } of plan) {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    writeAtomic(dest, readBounded(blobFile(from, e.digest), BUNDLE_LIMITS.maxBlobBytes));
    written.push(e.name);
  }
  return { ok: true, errors: [], written, bundleDigest: v.bundleDigest, replay: v.replay };
}


/***/ }),

/***/ 67439:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   TJ: () => (/* binding */ buildProgressView)
/* harmony export */ });
/* unused harmony exports PROGRESS_SCHEMA, PROGRESS_VERSION, FINDINGS_SCHEMA, aggregateFindings, reviewItemsFromInvariantCoverage, reviewItemsFromBoundaryContexts, portfolioProgressFields, attachPortfolioProgress */
/* harmony import */ var _assurance_config_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(90385);
/* harmony import */ var _bundle_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(33889);
/* harmony import */ var _wording_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(9886);
/* harmony import */ var _scheduler_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(34563);
/* harmony import */ var _work_units_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(90987);
// Coverage-aware portfolio progress and review views (X-707).
//
// ONE projection for every surface, in the pattern of lineage/deployment/projection.js: the CLI (`agentic-security portfolio progress`),
// the MCP tool (`portfolio_progress`) and the fleet summary all call `buildProgressView`, so none formats its own progress text and the
// surfaces cannot disagree. It is a VIEW: it reads a verified store and ledger and invents nothing.
//
// What it keeps apart (X-707.AC01), because adding them together is how a portfolio looks finished when it is not:
//   verified    units whose result is current and complete. The only count that is progress.
//   problems    blocked, failed, canceled and stale units, each listed with its reason. A stale unit is one whose earlier result was
//               invalidated by a changed input; it is pending again and its old result does not count.
//   coverage    per repository, how many of its units are verified, and whether the repository is fully verified, partial or not started.
//   budget      per limit: the limit (or `null` when none is enforced), what is used, what in-flight attempts hold, what remains.
//   review      what a human still has to look at: blocked units, contracts awaiting approval, boundaries that could not be resolved.
//
// Aggregate findings (X-707.AC02) deduplicate by STABLE IDENTITY only. Two findings with the same `stableId` are one aggregate finding
// with every occurrence kept (repository, environment, release, commit, file, line, severity). The affected releases are listed
// separately, per finding and per release. A finding with no stable id is never merged by guesswork: it stays its own row, listed apart.
//
// Liveness (X-707.AC03). A worker's last sign of life is the newest of its heartbeat and its lease events. Beyond the declared
// `HEARTBEAT.staleAfterMs` it is `stale` and stays in the view with its age: a stale worker is never dropped from the report to make it
// look healthier, and its output is irrelevant (nothing here reads stdout). A controller that has finished is reported as FINISHED, which
// is not the same as every unit verified, which is not the same as every repository passing; the view says each separately and never
// states that the portfolio passed.
//
// Strings from the store (failure reasons) are checked for secret shapes before they are shown. Pure given its inputs: no clock (`now`
// is an argument), no randomness, fixed key order.







const PROGRESS_SCHEMA = 'agentic-security/portfolio-progress';
const PROGRESS_VERSION = '1.0.0';
const FINDINGS_SCHEMA = 'agentic-security/portfolio-findings';
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const MAX_STRING = 300;
const MAX_LIST = 200;

const safe = (s) => {
  const t = String(s ?? '').slice(0, MAX_STRING);
  return (0,_bundle_js__WEBPACK_IMPORTED_MODULE_1__/* .findSecret */ .mt)(t) ? '[withheld: secret-shaped text]' : t;
};
const byKey = (k) => (a, b) => (a[k] < b[k] ? -1 : a[k] > b[k] ? 1 : 0);
const cap = (list) => ({ items: list.slice(0, MAX_LIST), truncated: list.length > MAX_LIST, total: list.length });

// ---------------------------------------------------------------- aggregate findings (X-707.AC02)

/**
 * @param {Array<{ repository: string, environment?: string, release?: string, commit?: string, evidenceRef?: string, finding: object }>} entries
 *   each occurrence of a finding in one repository/environment/release
 */
function aggregateFindings(entries, { blockingSeverity = 'high' } = {}) {
  const rank = (s) => SEVERITY_RANK[s] ?? -1;
  const groups = new Map();
  const unidentified = [];
  let occurrences = 0;
  for (const e of Array.isArray(entries) ? entries : []) {
    const f = e?.finding;
    if (!e || typeof e.repository !== 'string' || !f || typeof f !== 'object') continue;
    occurrences += 1;
    const occ = {
      repository: e.repository, environment: e.environment ?? null, release: e.release ?? null, commit: e.commit ?? null,
      file: typeof f.file === 'string' ? f.file : null, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity ?? null, evidenceRef: e.evidenceRef ?? null,
    };
    if (typeof f.stableId !== 'string' || !f.stableId) { unidentified.push({ ...occ, vuln: safe(f.vuln), cwe: f.cwe ?? null, note: 'no stable id: not merged with any other finding' }); continue; }
    if (!groups.has(f.stableId)) groups.set(f.stableId, { identity: f.stableId, vuln: safe(f.vuln), cwe: f.cwe ?? null, family: f.family ?? null, occurrences: [] });
    groups.get(f.stableId).occurrences.push(occ);
  }
  const items = [...groups.values()].sort(byKey('identity')).map((g) => {
    g.occurrences.sort((a, b) => `${a.repository}|${a.environment}|${a.release}|${a.file}|${a.line}`.localeCompare(`${b.repository}|${b.environment}|${b.release}|${b.file}|${b.line}`));
    const sev = g.occurrences.reduce((m, o) => (rank(o.severity) > rank(m) ? o.severity : m), null);
    const uniq = (k) => [...new Set(g.occurrences.map((o) => o[k]).filter((v) => v !== null))].sort();
    return { ...g, severity: sev, severities: uniq('severity'), repositories: uniq('repository'), environments: uniq('environment'), affectedReleases: uniq('release'), occurrenceCount: g.occurrences.length };
  });
  const byRelease = {};
  for (const it of items) for (const r of it.affectedReleases) (byRelease[r] ??= []).push(it.identity);
  const bySeverity = {};
  for (const it of items) bySeverity[it.severity ?? 'unknown'] = (bySeverity[it.severity ?? 'unknown'] ?? 0) + 1;
  const blockingRepos = new Set();
  for (const it of items) for (const o of it.occurrences) if (rank(o.severity) >= rank(blockingSeverity)) blockingRepos.add(o.repository);
  for (const o of unidentified) if (rank(o.severity) >= rank(blockingSeverity)) blockingRepos.add(o.repository);
  return {
    schema: FINDINGS_SCHEMA, schemaVersion: PROGRESS_VERSION, occurrences, unique: items.length, blockingSeverity,
    items, unidentified: unidentified.sort((a, b) => `${a.repository}|${a.file}|${a.line}`.localeCompare(`${b.repository}|${b.file}|${b.line}`)),
    byRelease: Object.fromEntries(Object.keys(byRelease).sort().map((k) => [k, byRelease[k].sort()])),
    bySeverity: Object.fromEntries(Object.keys(bySeverity).sort().map((k) => [k, bySeverity[k]])),
    repositoriesWithBlockingFindings: [...blockingRepos].sort(),
  };
}

// ---------------------------------------------------------------- review queue sources

/** Review items from a business coverage report (posture/invariants/coverage.js): contracts that are not approved. */
function reviewItemsFromInvariantCoverage(coverage) {
  const out = [];
  for (const i of coverage?.invariants ?? []) {
    if (i.state !== 'approved') out.push({ kind: 'contract-approval', id: i.id ?? i.key, repository: null, reason: `contract '${safe(i.key)}' is ${safe(i.state)}: a violation of it is advisory until a reviewer approves it`, source: 'invariant-coverage' });
  }
  return out;
}

/** Review items from boundary contexts (lineage/deployment/projection.js): findings whose deployment exposure is unresolved or unbound. */
function reviewItemsFromBoundaryContexts(contexts) {
  const out = [];
  for (const c of Array.isArray(contexts) ? contexts : []) {
    if (!c || typeof c !== 'object') continue;
    const unresolved = c.exposure?.state === 'unresolved';
    const unbound = c.binding && c.binding.status !== 'bound';
    if (unresolved || unbound) out.push({ kind: 'boundary-resolution', id: c.id ?? null, repository: c.finding?.repository ?? null, reason: unresolved ? 'deployment reachability is unresolved: a person must decide whether the path is real' : 'the finding is not bound to a deployed service', source: 'deployment-boundaries' });
  }
  return out;
}

// ---------------------------------------------------------------- the view

const lastSignal = (u, ledger) => {
  const attemptId = u.lease?.attemptId;
  let at = 0;
  for (const e of u.events) if (e.attemptId === attemptId && typeof e.at === 'number' && e.at > at) at = e.at;
  const hb = attemptId ? ledger.heartbeats?.[attemptId]?.at : null;
  return Math.max(at, typeof hb === 'number' ? hb : 0);
};

/**
 * @param {object} p
 * @param {object} p.store      a verified portfolio store
 * @param {object} [p.ledger]   the scheduler ledger (usage, reservations, heartbeats, cancellations)
 * @param {object} [p.budgets]  the budgets the scheduler runs under
 * @param {number} p.now        milliseconds
 * @param {Array}  [p.reviewItems]
 * @param {Array}  [p.findings] occurrences for `aggregateFindings`
 * @param {string} [p.blockingSeverity]
 * @param {{ intervalMs: number, staleAfterMs: number }} [p.heartbeat]
 */
function buildProgressView({ store, ledger = null, budgets = null, now, reviewItems = [], findings = null, blockingSeverity = 'high', heartbeat = _scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .HEARTBEAT */ .rU } = {}) {
  if (!store || typeof store.units !== 'object') return { ok: false, errors: [{ code: 'NO_STORE', message: 'a verified portfolio store is required' }] };
  if (!Number.isFinite(now)) return { ok: false, errors: [{ code: 'NO_NOW', message: 'now (milliseconds) is required; the view reads no clock' }] };
  const led = ledger ?? { usage: { portfolio: {}, repositories: {} }, reservations: {}, heartbeats: {}, cancellations: [], overruns: [] };
  const units = Object.values(store.units).sort(byKey('id'));
  const ref = (u) => ({ unitId: u.id, repository: u.repository, taskType: u.taskType });

  const count = Object.fromEntries(_work_units_js__WEBPACK_IMPORTED_MODULE_4__/* .UNIT_STATES */ .Yc.map((s) => [s, 0]));
  for (const u of units) count[u.state] += 1;
  const lastEvent = (u, type) => [...u.events].reverse().find((e) => e.type === type);
  const blocked = units.filter((u) => u.state === 'blocked').map((u) => ({ ...ref(u), reason: safe(u.blockedReason) }));
  const failed = units.filter((u) => u.state === 'failed').map((u) => ({ ...ref(u), retryCount: u.retryCount, reason: safe(lastEvent(u, 'failed')?.reason ?? (lastEvent(u, 'expired') ? 'lease expired' : 'failed')) }));
  const canceled = units.filter((u) => u.state === 'canceled').map((u) => ({ ...ref(u), reason: safe(lastEvent(u, 'canceled')?.reason) }));
  const stale = units.filter((u) => u.stale.length && u.state !== 'verified').map((u) => ({ ...ref(u), state: u.state, staleResults: u.stale.length, reason: 'an earlier result was invalidated by a changed input and does not count', changedDimensions: u.stale.at(-1)?.changedDimensions ?? null }));

  // workers: every lease holder, live or stale
  const workers = units.filter((u) => u.state === 'leased' || u.state === 'running').map((u) => {
    const last = lastSignal(u, led);
    const age = Math.max(0, now - last);
    return { ...ref(u), holder: u.lease.holder, attemptId: u.lease.attemptId, state: u.state, lastSignalAt: last || null, ageMs: age, status: !last ? 'no-heartbeat' : age > heartbeat.staleAfterMs ? 'stale' : 'live', leaseExpiresAt: u.lease.expiresAt };
  }).sort(byKey('attemptId'));

  // coverage by repository
  const repos = new Map();
  for (const u of units) {
    if (!repos.has(u.repository)) repos.set(u.repository, { repository: u.repository, commit: u.commit, units: 0, verified: 0, problems: 0, inFlight: 0, pending: 0 });
    const r = repos.get(u.repository);
    r.units += 1;
    if (u.state === 'verified') r.verified += 1;
    else if (u.state === 'blocked' || u.state === 'failed' || u.state === 'canceled') r.problems += 1;
    else if (u.state === 'leased' || u.state === 'running') r.inFlight += 1;
    else r.pending += 1;
  }
  const coverageRepos = [...repos.values()].sort(byKey('repository')).map((r) => ({ ...r, status: r.verified === r.units ? 'fully-verified' : r.verified > 0 ? 'partial' : r.problems > 0 ? 'incomplete' : 'not-started' }));
  const fully = coverageRepos.filter((r) => r.status === 'fully-verified').length;

  // budget
  const reserved = { portfolio: {}, repositories: {} };
  for (const r of Object.values(led.reservations ?? {})) {
    reserved.portfolio.count = (reserved.portfolio.count ?? 0) + 1;
    for (const d of _scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .DIMENSIONS */ .Yf) reserved.portfolio[d] = (reserved.portfolio[d] ?? 0) + r[d];
    reserved.repositories[r.repository] ??= { count: 0 };
    reserved.repositories[r.repository].count += 1;
    for (const d of _scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .DIMENSIONS */ .Yf) reserved.repositories[r.repository][d] = (reserved.repositories[r.repository][d] ?? 0) + r[d];
  }
  const dimView = (limits, used, held) => {
    const o = {};
    for (const d of [..._scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .DIMENSIONS */ .Yf, 'concurrency']) {
      const limit = Number.isFinite(limits?.[d]) ? limits[d] : null;
      const u = d === 'concurrency' ? (held?.count ?? 0) : (used?.[d] ?? 0);
      const h = d === 'concurrency' ? 0 : (held?.[d] ?? 0);
      o[d] = { limit, used: u, reserved: h, remaining: limit === null ? null : Math.max(0, limit - u - h), enforced: limit !== null };
    }
    return o;
  };
  const repoLimits = (name) => ({ ...(budgets?.repositories?.default ?? {}), ...(budgets?.repositories?.[name] ?? {}) });
  const budget = {
    declared: !!budgets,
    portfolio: dimView(budgets?.portfolio, led.usage?.portfolio, reserved.portfolio),
    repositories: Object.fromEntries(coverageRepos.map((r) => [r.repository, dimView(repoLimits(r.repository), led.usage?.repositories?.[r.repository], reserved.repositories[r.repository])])),
    overruns: (led.overruns ?? []).length,
  };

  // review queue
  const review = [
    ...blocked.map((b) => ({ kind: 'blocked-unit', id: b.unitId, repository: b.repository, reason: b.reason, source: 'portfolio' })),
    ...(Array.isArray(reviewItems) ? reviewItems : []).map((i) => ({ kind: String(i.kind ?? 'review'), id: i.id ?? null, repository: i.repository ?? null, reason: safe(i.reason), source: String(i.source ?? 'supplied') })),
  ];
  const reviewByKind = {};
  for (const r of review) reviewByKind[r.kind] = (reviewByKind[r.kind] ?? 0) + 1;

  const aggregate = Array.isArray(findings) ? aggregateFindings(findings, { blockingSeverity }) : null;
  const inFlight = count.leased + count.running;
  const total = units.length;
  const controllerFinished = inFlight === 0 && count.pending === 0;
  const allVerified = total > 0 && count.verified === total;
  const nonVerified = total - count.verified;
  const completion = {
    controllerFinished,
    allUnitsVerified: allVerified,
    repositoriesFullyVerified: { n: fully, of: coverageRepos.length },
    findingsSupplied: aggregate !== null,
    repositoriesWithBlockingFindings: aggregate ? aggregate.repositoriesWithBlockingFindings : null,
    passAssessment: 'not-implied',
    statement: controllerFinished && !allVerified
      ? `The controller has finished, but ${nonVerified} of ${total} unit(s) are not verified (${count.blocked} blocked, ${count.failed} failed, ${count.canceled} canceled${count.pending ? `, ${count.pending} pending` : ''}). Finished does not mean every repository was checked, and it does not mean any repository passed.`
      : controllerFinished && allVerified
        ? `Every planned unit is verified (${total} of ${total}) in ${fully} of ${coverageRepos.length} repositories. That means the planned checks completed; it does not mean every repository passed${aggregate ? `: ${aggregate.repositoriesWithBlockingFindings.length} repositor${aggregate.repositoriesWithBlockingFindings.length === 1 ? 'y has' : 'ies have'} ${blockingSeverity}-or-worse findings in the supplied results` : ' (findings were not supplied to this view)'}.`
        : `The controller has not finished: ${count.verified} of ${total} unit(s) verified, ${inFlight} in flight, ${count.pending} pending.`,
  };

  const staleWorkers = workers.filter((w) => w.status !== 'live');
  const lines = [
    `Portfolio progress (${store.synthetic ? 'SYNTHETIC; ' : ''}as of ${now}): ${count.verified}/${total} unit(s) verified; ${fully}/${coverageRepos.length} repositor${coverageRepos.length === 1 ? 'y' : 'ies'} fully verified`,
    `  Not verified: ${count.blocked} blocked, ${count.failed} failed, ${count.canceled} canceled, ${stale.length} stale, ${count.pending} pending, ${inFlight} in flight`,
    `  Workers: ${workers.length - staleWorkers.length} live, ${staleWorkers.length} stale or silent (stale after ${heartbeat.staleAfterMs} ms without a heartbeat)`,
    `  Budget: ${budgets ? _scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .DIMENSIONS */ .Yf.filter((d) => budget.portfolio[d].enforced).map((d) => `${d} ${budget.portfolio[d].remaining} left`).join(', ') || 'no portfolio limit enforced' : 'not declared to this view'}`,
    `  Pending human review: ${review.length}${review.length ? ` (${Object.keys(reviewByKind).sort().map((k) => `${k}: ${reviewByKind[k]}`).join(', ')})` : ''}`,
    `  ${completion.statement}`,
    `  ${_wording_js__WEBPACK_IMPORTED_MODULE_2__/* .NOT_A_GUARANTEE */ .zi}`,
  ];
  return {
    ok: true,
    view: {
      schema: PROGRESS_SCHEMA, schemaVersion: PROGRESS_VERSION, ...(store.synthetic ? { synthetic: true } : {}), planId: store.planId, asOf: now,
      heartbeat: { intervalMs: heartbeat.intervalMs, staleAfterMs: heartbeat.staleAfterMs },
      units: { total, verified: count.verified, pending: count.pending, inFlight, blocked: cap(blocked), failed: cap(failed), canceled: cap(canceled), stale: cap(stale), counts: count },
      workers: { items: workers, stale: staleWorkers.length, live: workers.length - staleWorkers.length },
      coverage: { repositories: coverageRepos, fullyVerified: fully, total: coverageRepos.length },
      budget,
      review: { pending: review.length, byKind: Object.fromEntries(Object.keys(reviewByKind).sort().map((k) => [k, reviewByKind[k]])), ...cap(review) },
      cancellations: (led.cancellations ?? []).map((c) => ({ scope: c.scope, reason: safe(c.reason), at: c.at })),
      findings: aggregate,
      completion,
      lines,
    },
  };
}

/** The additive field a surface asks for: `{ portfolioProgress }`, or `{}` when the feature is off, so flag-off output is unchanged. */
function portfolioProgressFields({ config, ...input } = {}) {
  if (!config || featureStatus(config, FEATURE_ID).status !== 'ok') return {};
  const r = buildProgressView(input);
  return r.ok ? { portfolioProgress: r.view } : { portfolioProgressErrors: r.errors };
}

/** Attach the view to a fleet rollup. Flag off: the SAME object comes back untouched. */
function attachPortfolioProgress(rollup, input) {
  const extra = portfolioProgressFields(input);
  return Object.keys(extra).length ? { ...rollup, ...extra } : rollup;
}


/***/ }),

/***/ 34563:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   GN: () => (/* binding */ ledgerPathFor),
/* harmony export */   SC: () => (/* binding */ readLedger),
/* harmony export */   Yf: () => (/* binding */ DIMENSIONS),
/* harmony export */   rU: () => (/* binding */ HEARTBEAT)
/* harmony export */ });
/* unused harmony exports LEDGER_SCHEMA, WEIGHT_RANGE, SKIP_CODES, validateBudgets, newLedger, selectUnit, scheduleNext, settleAttempt, heartbeat, routingBudgetFor, spendBoundOf, chargeModelSpend, createCancelScope, runScheduled */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _sandbox_supervise_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(74676);
/* harmony import */ var _work_units_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(90987);
// Bounded portfolio scheduler: budgets, fairness and scoped cancellation (X-706).
//
// work-units.js gives durable, leased units but hands out the next pending unit in id order, with no notion of cost and no notion of
// who is waiting. This module decides WHICH unit is leased next, and whether ANY unit may be leased at all, from five limits declared
// at two levels (the whole portfolio, and each repository): wall time, provider spend, concurrency, request count and storage.
//
// ADMISSION (X-706.AC01). The check happens BEFORE the lease, inside the same locked store transaction that creates the lease, so two
// processes cannot both squeeze under a limit. A unit must carry an ESTIMATE of what it can cost (an unknown cost is never zero: a unit
// with no estimate is not leased, and is reported `no-estimate`). Admission counts what has been used, plus what in-flight attempts have
// RESERVED, plus this unit's estimate. A refusal is one of two kinds, and they are reported separately:
//   at-capacity  would fit once an in-flight attempt settles (a wait)
//   exhausted    would not fit even with nothing in flight (will not recover without a larger budget)
// An attempt that ends without a usage report (expired, failed, canceled) is charged its whole reservation, because what it spent is
// unknown. A reported overrun of the estimate is recorded and shrinks what remains; it is detected, not rolled back. Wall time is also
// enforced while the unit runs: the executor's signal aborts at the unit's wall estimate (capped by what the portfolio has left).
//
// FAIRNESS (X-706.AC02). Priority is a WEIGHT, not an order. Among repositories that currently have an admissible unit, the next lease
// goes to the one with the lowest `leasesGranted / weight` (weights are integers 1..8, default 1; ties break on repository name, and
// within a repository on unit id). Consequences, each tested:
//   - no starvation: a repository that is admissible is served within a bounded number of leases whatever the others hold, so a
//     repository with 300 units cannot hold back one with 1;
//   - priority shifts the SHARE, it never removes it: weight 8 against weight 1 is served about eight times as often, and the
//     weight-1 repository is still served;
//   - a repository that was blocked for a long time is owed service and is served first when it is admissible again (a bounded burst);
//   - a blocked repository (declared blocked, over its own budget, or with every unit blocked) is SKIPPED, never waited on. The skip
//     reason is returned per repository, so a stall is visible instead of silent.
// A unit whose estimate cannot fit the remaining budget is never leased and never blocks a smaller sibling.
//
// CANCELLATION (X-706.AC03). A cancellation names a scope (one unit, one repository, or everything) and is recorded in the ledger, so a
// process that did not receive the call still honours it. For attempts running in THIS process the scope's AbortController is aborted;
// work started through `ctx.spawn` runs under sandbox/supervise.js, which terminates the whole process tree and reports survivors. A
// lease is RELEASED only when the attempt has settled and nothing survived; otherwise it is left to EXPIRE (so no other worker can start
// the same unit while a descendant may still be running) and the report says so. Verified units and their receipts are never touched.
// The report is always `incomplete` with a reason when anything in scope was not verified.
//
// SPEND (routing). `routingBudgetFor` gives the routing policy the remaining dollars (portfolio and repository, less reservations), and
// `chargeModelSpend` refuses a routing decision that is blocked, has no upper cost bound, or would exceed the unit's reservation.
// No provider is called here; the executor does that through an injected transport.
//
// Heartbeats are recorded with the lease renewal. Nothing here reads a clock except where a function takes `clock`/`now`.






const LEDGER_SCHEMA = 'agentic-security/portfolio-ledger';
const LEDGER_VERSION = 1;
const DIMENSIONS = Object.freeze(['wallMs', 'spendUsd', 'requests', 'storageBytes']);
const WEIGHT_RANGE = Object.freeze({ min: 1, max: 8, default: 1 });
const HEARTBEAT = Object.freeze({ intervalMs: 5000, staleAfterMs: 15000 });
const SKIP_CODES = Object.freeze(['repository-blocked', 'no-estimate', 'at-capacity', 'exhausted', 'canceled']);
const MAX_LEDGER_BYTES = 16 * 1024 * 1024;

const zero = () => ({ wallMs: 0, spendUsd: 0, requests: 0, storageBytes: 0 });
const isNum = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

// ---------------------------------------------------------------- budgets

/**
 * Budgets: `{ portfolio: { concurrency, wallMs, spendUsd, requests, storageBytes }, repositories?: { default?, [name]: partial limits },
 * priorities?: { [name]: weight } }`. Every portfolio limit is REQUIRED (an unlimited portfolio is a decision to make out loud, not a
 * default); a repository limit that is absent is not enforced for that repository and the view says so.
 */
function validateBudgets(b) {
  const errors = [];
  const bad = (p, message) => errors.push({ code: 'BAD_BUDGETS', path: p, message });
  if (!b || typeof b !== 'object') return { ok: false, errors: [{ code: 'BAD_BUDGETS', path: '', message: 'not an object' }] };
  const lim = (o, p, required) => {
    if (!o || typeof o !== 'object') { if (required) bad(p, 'required'); return; }
    if (o.concurrency !== undefined && !(Number.isInteger(o.concurrency) && o.concurrency >= 1 && o.concurrency <= 64)) bad(`${p}.concurrency`, 'an integer in 1..64');
    else if (required && o.concurrency === undefined) bad(`${p}.concurrency`, 'required');
    for (const d of DIMENSIONS) {
      if (o[d] === undefined) { if (required) bad(`${p}.${d}`, 'required'); } else if (!isNum(o[d])) bad(`${p}.${d}`, 'a finite non-negative number');
    }
  };
  lim(b.portfolio, 'portfolio', true);
  for (const [name, o] of Object.entries(b.repositories ?? {})) lim(o, `repositories.${name}`, false);
  for (const [name, w] of Object.entries(b.priorities ?? {})) {
    if (!(Number.isInteger(w) && w >= WEIGHT_RANGE.min && w <= WEIGHT_RANGE.max)) bad(`priorities.${name}`, `an integer weight in ${WEIGHT_RANGE.min}..${WEIGHT_RANGE.max}`);
  }
  return { ok: errors.length === 0, errors };
}

const limitsFor = (budgets, repo) => ({ ...(budgets.repositories?.default ?? {}), ...(budgets.repositories?.[repo] ?? {}) });
const weightOf = (budgets, repo) => budgets.priorities?.[repo] ?? WEIGHT_RANGE.default;

// ---------------------------------------------------------------- ledger

const ledgerPathFor = (storeFile) => `${storeFile}.ledger.json`;

function newLedger() {
  return { schema: LEDGER_SCHEMA, version: LEDGER_VERSION, usage: { portfolio: zero(), repositories: {} }, reservations: {}, grants: {}, heartbeats: {}, cancellations: [], overruns: [], settled: {} };
}

function readLedger(storeFile) {
  const file = ledgerPathFor(storeFile);
  let raw;
  try {
    const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_LEDGER_BYTES) throw (0,_work_units_js__WEBPACK_IMPORTED_MODULE_3__/* .typedError */ .Zz)('LEDGER_CORRUPT', 'ledger is not a regular file within the size limit');
    raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8');
  } catch (e) { if (e.code === 'ENOENT') return newLedger(); throw e; }
  let l;
  try { l = JSON.parse(raw); } catch { throw (0,_work_units_js__WEBPACK_IMPORTED_MODULE_3__/* .typedError */ .Zz)('LEDGER_CORRUPT', 'ledger is not valid JSON'); }
  if (!l || l.schema !== LEDGER_SCHEMA || l.version !== LEDGER_VERSION || typeof l.reservations !== 'object' || typeof l.usage !== 'object') throw (0,_work_units_js__WEBPACK_IMPORTED_MODULE_3__/* .typedError */ .Zz)('LEDGER_CORRUPT', 'not a portfolio ledger of a supported version');
  return l;
}

function writeLedger(storeFile, ledger) {
  const file = ledgerPathFor(storeFile);
  const tmp = `${file}.tmp-${process.pid}`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(ledger), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const repoUsage = (ledger, repo) => (ledger.usage.repositories[repo] ??= zero());
const add = (a, b) => { for (const d of DIMENSIONS) a[d] += b[d] ?? 0; };

/** Charge an attempt's reservation to usage and release it. `usage` null charges the whole reservation (what it spent is unknown). Idempotent. */
function settle(ledger, attemptId, usage, how) {
  const r = ledger.reservations[attemptId];
  if (!r) return null;
  const charge = {};
  const over = [];
  for (const d of DIMENSIONS) {
    charge[d] = usage && isNum(usage[d]) ? usage[d] : r[d];
    if (usage && isNum(usage[d]) && usage[d] > r[d]) over.push(d);
  }
  add(ledger.usage.portfolio, charge); add(repoUsage(ledger, r.repository), charge);
  if (over.length) ledger.overruns.push({ attemptId, unitId: r.unitId, repository: r.repository, dimensions: over });
  delete ledger.reservations[attemptId];
  delete ledger.heartbeats[attemptId];
  ledger.settled[attemptId] = how;
  return { charge, over };
}

const inScope = (unit, scope) => !!scope && (scope.all === true || (scope.unitId && scope.unitId === unit.id) || (scope.repository && scope.repository === unit.repository));

/** Settle reservations whose lease ended and cancel pending units inside a recorded cancellation scope. Returns what changed. */
function reconcile(store, ledger, now) {
  const recovered = recoverExpired(store, now);
  const settledNow = [];
  for (const [attemptId, r] of Object.entries(ledger.reservations)) {
    const u = store.units[r.unitId];
    if (!u || !u.lease || u.lease.attemptId !== attemptId) { settle(ledger, attemptId, null, 'lease-ended'); settledNow.push(attemptId); }
  }
  const canceled = [];
  for (const c of ledger.cancellations) {
    for (const u of Object.values(store.units)) {
      if ((u.state === 'pending' || u.state === 'blocked') && inScope(u, c.scope)) { cancelUnits(store, { unitId: u.id, reason: c.reason, now }); canceled.push(u.id); }
    }
  }
  return { recovered, settled: settledNow, canceled };
}

// ---------------------------------------------------------------- admission and selection

function checkLimits(limits, used, flight, flightCount, est, scope) {
  const out = [];
  if (Number.isInteger(limits.concurrency) && flightCount >= limits.concurrency) out.push({ code: 'at-capacity', scope, dimension: 'concurrency', limit: limits.concurrency, inFlight: flightCount });
  for (const d of DIMENSIONS) {
    if (!isNum(limits[d])) continue;
    if (used[d] + est[d] > limits[d]) out.push({ code: 'exhausted', scope, dimension: d, limit: limits[d], used: used[d], needed: est[d] });
    else if (used[d] + flight[d] + est[d] > limits[d]) out.push({ code: 'at-capacity', scope, dimension: d, limit: limits[d], used: used[d], reserved: flight[d], needed: est[d] });
  }
  return out;
}

function normalizeEstimate(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const e = {};
  for (const d of DIMENSIONS) { if (!isNum(raw[d])) return null; e[d] = raw[d]; }
  return e.wallMs > 0 ? e : null;
}

/** What each repository and the portfolio currently have reserved by in-flight attempts. */
function flightOf(ledger) {
  const portfolio = { ...zero(), count: 0 };
  const repos = {};
  for (const r of Object.values(ledger.reservations)) {
    const rr = (repos[r.repository] ??= { ...zero(), count: 0 });
    for (const d of DIMENSIONS) { portfolio[d] += r[d]; rr[d] += r[d]; }
    portfolio.count += 1; rr.count += 1;
  }
  return { portfolio, repos };
}

/**
 * Pure selection over a reconciled store and ledger: the unit that would be leased next, or why none can be.
 * @returns {{ unit: object|null, estimate: object|null, skipped: Array, idle: boolean, waiting: boolean }}
 */
function selectUnit({ store, ledger, budgets, estimateOf, blockedRepositories = [] }) {
  const flight = flightOf(ledger);
  const pendingByRepo = new Map();
  for (const u of Object.values(store.units).sort((a, b) => (a.id < b.id ? -1 : 1))) {
    if (u.state === 'pending') { if (!pendingByRepo.has(u.repository)) pendingByRepo.set(u.repository, []); pendingByRepo.get(u.repository).push(u); }
  }
  const skipped = [];
  const blocked = new Set(blockedRepositories);
  const candidates = [];
  for (const [repo, units] of [...pendingByRepo].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (blocked.has(repo)) { skipped.push({ repository: repo, code: 'repository-blocked', detail: 'declared blocked; its units are skipped and independent repositories continue' }); continue; }
    const repoFlight = flight.repos[repo] ?? { ...zero(), count: 0 };
    const repoLimits = limitsFor(budgets, repo);
    let pick = null; const unitSkips = [];
    for (const u of units) {
      const est = normalizeEstimate(estimateOf(u));
      if (!est) { unitSkips.push({ repository: repo, unitId: u.id, code: 'no-estimate', detail: 'no cost estimate, and an unknown cost is never treated as zero' }); continue; }
      const refusals = [
        ...checkLimits(budgets.portfolio, ledger.usage.portfolio, flight.portfolio, flight.portfolio.count, est, 'portfolio'),
        ...checkLimits(repoLimits, repoUsage(ledger, repo), repoFlight, repoFlight.count, est, 'repository'),
      ];
      if (refusals.length) {
        const code = refusals.some((r) => r.code === 'exhausted') ? 'exhausted' : 'at-capacity';
        unitSkips.push({ repository: repo, unitId: u.id, code, detail: refusals.map((r) => `${r.scope} ${r.dimension}`).join(', '), refusals });
        continue;
      }
      pick = { unit: u, estimate: est };
      break;
    }
    skipped.push(...unitSkips.filter((s) => !pick || s.unitId !== pick.unit.id));
    if (pick) candidates.push({ repo, ...pick });
  }
  let chosen = null;
  for (const c of candidates) {
    const score = (ledger.grants[c.repo] ?? 0) / weightOf(budgets, c.repo);
    if (!chosen || score < chosen.score) chosen = { ...c, score };
  }
  const idle = pendingByRepo.size === 0;
  return { unit: chosen ? chosen.unit : null, estimate: chosen ? chosen.estimate : null, skipped, idle, waiting: !chosen && skipped.some((s) => s.code === 'at-capacity') };
}

/**
 * Admit and lease the next unit in ONE locked transaction. Returns `{ lease, ... }` or `{ lease: null, idle, waiting, skipped }`.
 * A repeat `requestId` from the same holder returns the existing lease and reserves nothing more.
 */
function scheduleNext(file, { budgets, estimateOf, holder, now, ttlMs, requestId = null, blockedRepositories = [] }) {
  const bv = validateBudgets(budgets);
  if (!bv.ok) throw typedError('BAD_BUDGETS', `invalid budgets: ${bv.errors[0].path} ${bv.errors[0].message}`, { errors: bv.errors });
  return mutateStore(file, (store) => {
    const ledger = readLedger(file);
    const changed = reconcile(store, ledger, now);
    const finish = (out) => { writeLedger(file, ledger); return { ...out, reconciled: changed }; };
    if (requestId) {
      for (const u of Object.values(store.units)) {
        if (u.lease && u.lease.requestId === requestId && u.lease.holder === holder) {
          return finish({ lease: { unitId: u.id, attemptId: u.lease.attemptId, expiresAt: u.lease.expiresAt, repository: u.repository, duplicate: true }, idle: false, waiting: false, skipped: [] });
        }
      }
    }
    const sel = selectUnit({ store, ledger, budgets, estimateOf, blockedRepositories });
    if (!sel.unit) return finish({ lease: null, idle: sel.idle, waiting: sel.waiting, skipped: sel.skipped });
    const l = leaseUnit(store, { holder, now, ttlMs, unitId: sel.unit.id, requestId });
    ledger.reservations[l.attemptId] = { unitId: sel.unit.id, repository: sel.unit.repository, holder, at: now, ...sel.estimate, used: { spendUsd: 0, requests: 0 } };
    ledger.grants[sel.unit.repository] = (ledger.grants[sel.unit.repository] ?? 0) + 1;
    return finish({ lease: { ...l, repository: sel.unit.repository, reservation: sel.estimate }, idle: false, waiting: false, skipped: sel.skipped });
  });
}

/** Settle an attempt's reservation (idempotent). `usage` null charges the whole reservation. */
function settleAttempt(file, { attemptId, usage = null, how = 'reported' }) {
  return mutateStore(file, () => {
    const ledger = readLedger(file);
    const r = settle(ledger, attemptId, usage, how);
    writeLedger(file, ledger);
    return r;
  });
}

/** Renew the lease and record a heartbeat in one transaction. */
function heartbeat(file, { unitId, attemptId, now, ttlMs }) {
  return mutateStore(file, (store) => {
    const ledger = readLedger(file);
    const r = renewLease(store, { unitId, attemptId, now, ttlMs });
    if (r.ok) {
      const u = store.units[unitId];
      ledger.heartbeats[attemptId] = { holder: u.lease.holder, unitId, repository: u.repository, at: now };
      writeLedger(file, ledger);
    }
    return r;
  });
}

// ---------------------------------------------------------------- routing and spend

/** What the routing policy may spend for a task in `repository` right now: the smaller of the portfolio and repository remainders, less reservations. */
function routingBudgetFor({ budgets, ledger, repository }) {
  const flight = flightOf(ledger);
  const left = (limit, used, reserved) => (isNum(limit) ? Math.max(0, limit - used - reserved) : Infinity);
  const p = left(budgets.portfolio.spendUsd, ledger.usage.portfolio.spendUsd, flight.portfolio.spendUsd);
  const r = left(limitsFor(budgets, repository).spendUsd, repoUsage(ledger, repository).spendUsd, (flight.repos[repository] ?? zero()).spendUsd);
  const remainingUsd = Math.min(p, r);
  return { remainingUsd: Number.isFinite(remainingUsd) ? remainingUsd : 0 };
}

/** The dollar upper bound of a routing decision, or null when the decision selects nothing or carries no bound. Unknown is never free. */
function spendBoundOf(decision) {
  if (!decision || (decision.status !== 'routed' && decision.status !== 'fallback') || !decision.selected) return null;
  const c = decision.expectedBounds?.costUsd;
  const bound = Math.max(isNum(c?.upperBound) ? c.upperBound : 0, isNum(c?.measuredMedian) ? c.measuredMedian : 0);
  return bound > 0 ? bound : null;
}

/** Charge one model request (a routing decision) against the attempt's reservation. Refuses when blocked, unbounded or over the reservation. */
function chargeModelSpend(file, { attemptId, decision }) {
  return mutateStore(file, () => {
    const ledger = readLedger(file);
    const r = ledger.reservations[attemptId];
    if (!r) return { ok: false, code: 'no-reservation', reason: 'this attempt holds no reservation (it ended, or was never admitted)' };
    const bound = spendBoundOf(decision);
    if (bound === null) return { ok: false, code: 'no-spend-bound', reason: 'the routing decision selects nothing or carries no cost bound; an unknown cost is not charged as zero and the request is not made' };
    if (r.used.requests + 1 > r.requests) return { ok: false, code: 'request-limit', reason: `the unit reserved ${r.requests} request(s)` };
    if (r.used.spendUsd + bound > r.spendUsd) return { ok: false, code: 'unit-spend-exceeded', reason: `needs up to ${bound} against ${r.spendUsd - r.used.spendUsd} remaining in the unit's reservation` };
    r.used.spendUsd += bound; r.used.requests += 1;
    writeLedger(file, ledger);
    return { ok: true, charged: bound };
  });
}

// ---------------------------------------------------------------- cancellation

/** Tracks the attempts running in this process so a scope can be cancelled. */
function createCancelScope() {
  const running = new Map();
  return {
    running,
    register(attemptId, entry) { running.set(attemptId, entry); },
    unregister(attemptId) { running.delete(attemptId); },
    /**
     * Cancel everything in `scope` ({ unitId } | { repository } | { all: true }).
     * @returns {Promise<object>} an `incomplete` report with the reason, what was released and what is left to expire
     */
    async cancel({ file, scope, reason, now, waitMs = 5000 }) {
      if (!scope || !(scope.all === true || scope.unitId || scope.repository)) throw typedError('BAD_SCOPE', 'a cancellation needs a scope: unitId, repository or all');
      const why = String(reason ?? 'canceled').slice(0, 300);
      mutateStore(file, (store) => {
        const ledger = readLedger(file);
        ledger.cancellations.push({ scope: { ...scope }, reason: why, at: now });
        reconcile(store, ledger, now);
        writeLedger(file, ledger);
      });
      const mine = [...running.entries()].filter(([, e]) => inScope({ id: e.unitId, repository: e.repository }, scope));
      for (const [, e] of mine) e.controller.abort(Object.assign(new Error(why), { code: 'CANCELED' }));
      await Promise.race([Promise.all(mine.map(([, e]) => e.settled)), new Promise((r) => setTimeout(r, waitMs))]);
      return mutateStore(file, (store) => {
        const ledger = readLedger(file);
        const report = { status: 'nothing-to-cancel', incomplete: false, reason: why, scope: { ...scope }, canceled: [], leasesReleased: [], leasesLeftToExpire: [], verifiedPreserved: [], survivors: [] };
        for (const id of Object.keys(store.units).sort()) {
          const u = store.units[id];
          if (!inScope(u, scope)) continue;
          if (u.state === 'verified') { report.verifiedPreserved.push(id); continue; }
          if (u.state === 'leased' || u.state === 'running') {
            const attemptId = u.lease.attemptId;
            const e = running.get(attemptId) ?? mine.find(([a]) => a === attemptId)?.[1];
            if (e && e.finished === true && e.survivors.length === 0) {
              cancelUnits(store, { unitId: id, reason: why, now });
              settle(ledger, attemptId, null, 'canceled');
              report.leasesReleased.push(id); report.canceled.push(id);
            } else {
              report.leasesLeftToExpire.push({ unitId: id, attemptId, expiresAt: u.lease.expiresAt, why: e ? (e.survivors.length ? 'a descendant survived termination' : 'the attempt did not settle in time') : 'the attempt runs in another process' });
              if (e?.survivors.length) report.survivors.push({ unitId: id, pids: e.survivors });
            }
          } else if (u.state === 'canceled') report.canceled.push(id);
        }
        if (report.canceled.length || report.leasesLeftToExpire.length) { report.status = 'incomplete'; report.incomplete = true; }
        writeLedger(file, ledger);
        return report;
      });
    },
  };
}

// ---------------------------------------------------------------- the driver

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Drive a store with budgets. `executor(unit, ctx)` returns `{ resultDigest, dependencies, usage? }` where `usage` may report
 * `{ spendUsd, requests, storageBytes }` (wall time is measured). `ctx` carries `attemptId`, `signal`, `heartbeat()`, `reservation`,
 * `spawn(bin, args, opts)` (supervised: the process tree ends with the attempt) and `requestModel(decision)` (charges the routing decision).
 *
 * With `backend`, the backend is probed before every lease; an unavailable one stops the run with `stopped: 'blocked'` and the typed probe
 * result in `blocked`. @returns {Promise<{ progress: object|null, stopped: string, order: string[], skipped: Array, blocked?: object }>}
 */
async function runScheduled({
  file, budgets, estimateOf, executor, holder = 'worker', clock = () => Date.now(), ttlMs, maxLeases = Infinity, cancelScope = null,
  blockedRepositories = [], heartbeatMs = HEARTBEAT.intervalMs, pollMs = 25, maxWaitMs = 2000, workers = null, backend = null,
}) {
  const bv = validateBudgets(budgets);
  if (!bv.ok) throw typedError('BAD_BUDGETS', `invalid budgets: ${bv.errors[0].path} ${bv.errors[0].message}`, { errors: bv.errors });
  const order = [];
  let leased = 0; let stopped = 'drained'; let lastSkipped = []; let blocked = null;
  const limit = Math.max(1, Math.min(workers ?? budgets.portfolio.concurrency, 16));
  let inFlight = 0;

  async function worker(n) {
    let waited = 0;
    for (;;) {
      if (leased >= maxLeases) { stopped = 'max-leases'; return; }
      // a shared backend that went away stops the run: nothing is written anywhere else instead (X-708.AC03)
      if (backend) { const p = backend.probe(); if (!p.ok) { stopped = 'blocked'; blocked = p; return; } }
      let r;
      try { r = scheduleNext(file, { budgets, estimateOf, holder: `${holder}-${n}`, now: clock(), ttlMs, blockedRepositories }); } catch (e) {
        if (backend && !backend.probe().ok) { stopped = 'blocked'; blocked = backend.probe(); return; }
        throw e;
      }
      lastSkipped = r.skipped;
      if (!r.lease) {
        if (r.idle) return;
        if (r.waiting) {
          if (inFlight === 0 && waited >= maxWaitMs) { stopped = 'waiting-timeout'; return; }
          await sleep(pollMs); waited += pollMs; continue;
        }
        stopped = 'nothing-schedulable'; return;
      }
      waited = 0;
      leased += 1; inFlight += 1;
      order.push(r.lease.unitId);
      try { await runOne(r.lease); } catch (e) {
        // the attempt could not record its outcome because the backend is gone: its lease is left to expire, never re-homed
        if (backend && !backend.probe().ok) { stopped = 'blocked'; blocked = backend.probe(); return; }
        throw e;
      } finally { inFlight -= 1; }
    }
  }

  async function runOne(lease) {
    const { unitId, attemptId } = lease;
    const controller = new AbortController();
    const entry = { unitId, repository: lease.repository, controller, finished: false, survivors: [], terminations: [], settled: null };
    let resolveSettled; entry.settled = new Promise((r) => { resolveSettled = r; });
    cancelScope?.register(attemptId, entry);
    const startedAt = clock();
    let timer = null; let beat = null;
    try {
      mutateStore(file, (s) => startUnit(s, { unitId, attemptId, now: clock() }));
      const unit = readStore(file).units[unitId];
      const wallCap = lease.reservation.wallMs;
      timer = setTimeout(() => controller.abort(Object.assign(new Error('wall-time budget for the unit was reached'), { code: 'WALL_TIMEOUT' })), wallCap);
      const doBeat = () => { try { heartbeat(file, { unitId, attemptId, now: clock(), ttlMs }); } catch { /* the lease is gone; the result will be refused */ } };
      beat = setInterval(doBeat, heartbeatMs); doBeat();
      const ctx = {
        attemptId, signal: controller.signal, reservation: lease.reservation, heartbeat: doBeat,
        async spawn(bin, args, opts = {}) {
          const r = await superviseSpawn(bin, args, { ...opts, signal: controller.signal });
          entry.terminations.push(r.termination);
          if (r.termination?.survivors?.length) entry.survivors.push(...r.termination.survivors);
          return r;
        },
        requestModel: (decision) => chargeModelSpend(file, { attemptId, decision }),
      };
      let res = null; let err = null;
      try { res = await executor(unit, ctx); } catch (e) { err = e; }
      clearTimeout(timer); clearInterval(beat);
      const canceled = controller.signal.aborted && controller.signal.reason?.code === 'CANCELED';
      if (canceled) return; // cancel() performs the store transition once this attempt has settled
      const timedOut = controller.signal.aborted && controller.signal.reason?.code === 'WALL_TIMEOUT';
      const spent = mutateStore(file, (s) => {
        const ledger = readLedger(file);
        const tracked = ledger.reservations[attemptId]?.used ?? { spendUsd: 0, requests: 0 };
        const failed = err || !res || timedOut;
        // a failed attempt spent an unknown amount: it is charged its reservation; a reported success is charged what it reported
        const usage = failed ? null : { wallMs: Math.max(1, clock() - startedAt), spendUsd: tracked.spendUsd, requests: tracked.requests, ...(res.usage ?? {}) };
        settle(ledger, attemptId, usage, failed ? 'failed' : 'reported');
        writeLedger(file, ledger);
        if (failed) failUnit(s, { unitId, attemptId, reason: timedOut ? 'wall-time budget reached' : err ? err.message : 'executor returned nothing', now: clock() });
        else completeUnit(s, { unitId, attemptId, resultDigest: res.resultDigest, dependencies: res.dependencies, now: clock() });
        return true;
      });
      void spent;
    } finally {
      clearTimeout(timer); clearInterval(beat);
      entry.finished = true;
      resolveSettled();
      cancelScope?.unregister(attemptId);
    }
  }

  await Promise.all(Array.from({ length: limit }, (_, i) => worker(i)));
  let progress = null;
  try { progress = progressOf(readStore(file)); } catch (e) { if (!blocked) throw e; }
  return { progress, stopped, order, skipped: lastSkipped, ...(blocked ? { blocked } : {}) };
}



/***/ }),

/***/ 90987:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   H9: () => (/* binding */ verifyStore),
/* harmony export */   Yc: () => (/* binding */ UNIT_STATES),
/* harmony export */   Zz: () => (/* binding */ typedError),
/* harmony export */   uz: () => (/* binding */ readStore)
/* harmony export */ });
/* unused harmony exports DEPENDENCY_DIMENSIONS, PORTFOLIO_LIMITS, planPortfolio, appendEvent, newStore, recoverExpired, leaseUnit, startUnit, renewLease, checkDependencies, completeUnit, failUnit, blockUnit, unblockUnit, cancelUnits, progressOf, scopedResults, fullyVerifiedRepositories, openStore, mutateStore, runPortfolio */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(98317);
/* harmony import */ var _assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(41877);
/* harmony import */ var _assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(53353);
// Durable, leased portfolio work units (X-704).
//
// fleet.js already gives a many-repository run isolation, bounded concurrency and a per-repository completed marker. What it cannot do
// is say WHICH unit of work was in flight when a process died, hand that unit to another worker without doing it twice, or refuse to
// count a half-finished attempt as progress. This module adds that, in the same local-first shape: one JSON file, written atomically,
// no server, no network.
//
//   PLAN      `planPortfolio` decomposes the AUTHORIZED repositories into units, one per (repository, exact commit, task type). A unit id
//             is a hash of those three and its required inputs, so the same plan always yields the same ids (X-704.AC01); a repository
//             that is not on the authorization list is excluded and disclosed, never silently planned.
//   STATES    pending, leased, running, verified, blocked, failed, canceled. A lease has an expiry; an expired lease is recovered into
//             pending (or failed once retries are spent). Every transition appends an event to the unit's attempt chain; the chain is
//             hash-linked, so an attempt record can be read and verified but not rewritten (X-704.AC02).
//   PROGRESS  only a unit in `verified` with a recorded result counts. A leased or running unit, a failed attempt, an expired lease and a
//             duplicate delivery of a completion all leave the count where it was (X-704.AC03).
//
// Operations are idempotent by attempt id: delivering the same `complete` twice records one verification; delivering a completion for a
// stale attempt (the lease expired and the unit moved on) is refused, because a zombie worker's result must not displace its successor's.
//
// The clock is an argument everywhere (`now`, milliseconds), so recovery is testable without sleeping and nothing here reads a clock.
// Persistence is `mutateStore`: an exclusive lock file, read, verify, change, write to a temporary file, rename. A store that fails
// verification is an error, never silently reset to empty.








const STORE_SCHEMA = 'agentic-security/portfolio-store';
const PLAN_SCHEMA = 'agentic-security/portfolio-plan';
const STORE_VERSION = 1;
const UNIT_STATES = Object.freeze(['pending', 'leased', 'running', 'verified', 'blocked', 'failed', 'canceled']);
const TASK_TYPES = Object.freeze(['sast-scan', 'sca-reachability', 'boundary-graph', 'invariant-scenarios', 'verification-replay', 'attestation']);
const DEPENDENCY_DIMENSIONS = Object.freeze(['code', 'policy', 'graph', 'invariant', 'oracle', 'toolchain']);

const PORTFOLIO_LIMITS = Object.freeze({
  maxUnits: 5000, maxEventsPerUnit: 400, maxStoreBytes: 32 * 1024 * 1024, defaultLeaseMs: 5 * 60_000, maxLeaseMs: 6 * 60 * 60_000, defaultMaxRetries: 2, maxRetries: 10,
  lockStaleMs: 30_000, lockWaitMs: 2000,
});

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

// ---------------------------------------------------------------- plan

const unitIdOf = (u) => `wu:${node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update((0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_3__/* .canonicalJson */ .dj)({ repository: u.repository, commit: u.commit, taskType: u.taskType, requiredInputs: u.requiredInputs })).digest('hex').slice(0, 16)}`;

/**
 * Decompose authorized repositories into stable work units.
 *
 * @param {object} a
 * @param {Array<{name:string, commit:string}>} a.repositories   candidates, each pinned to an exact commit
 * @param {string[]} a.authorized       the repository names the operator has authorized; anything else is excluded and disclosed
 * @param {string[]} a.taskTypes        task types to run per repository (from TASK_TYPES)
 * @param {Object<string,string[]>} [a.requiredInputs]  per task type, the named inputs the unit needs (e.g. ['source','policy'])
 */
function planPortfolio({ repositories = [], authorized = [], taskTypes = [], requiredInputs = {}, synthetic = false } = {}) {
  const errors = [];
  const rejected = [];
  const allow = new Set(authorized);
  for (const t of taskTypes) if (!TASK_TYPES.includes(t)) errors.push({ code: 'UNKNOWN_TASK_TYPE', message: `'${t}' is not a task type` });
  if (taskTypes.length === 0) errors.push({ code: 'NO_TASKS', message: 'a plan needs at least one task type' });
  const seen = new Set();
  const units = [];
  for (const r of repositories) {
    if (!r || typeof r.name !== 'string' || !r.name) { errors.push({ code: 'BAD_REPOSITORY', message: 'repository needs a name' }); continue; }
    if (!allow.has(r.name)) { rejected.push({ repository: r.name, reason: 'not-authorized' }); continue; }
    if (!isCommit(r.commit)) { errors.push({ code: 'UNBOUND_REVISION', message: `repository '${r.name}' is not pinned to an exact commit` }); continue; }
    if (seen.has(r.name)) { errors.push({ code: 'DUPLICATE_REPOSITORY', message: `repository '${r.name}' is listed twice` }); continue; }
    seen.add(r.name);
    for (const taskType of taskTypes) {
      const inputs = [...new Set(requiredInputs[taskType] ?? [])].sort();
      const u = { repository: r.name, commit: r.commit, taskType, requiredInputs: inputs };
      units.push({ id: unitIdOf(u), ...u });
    }
  }
  if (units.length > PORTFOLIO_LIMITS.maxUnits) errors.push({ code: 'TOO_MANY_UNITS', message: `plan has ${units.length} units; the limit is ${PORTFOLIO_LIMITS.maxUnits}` });
  units.sort((a, b) => (a.id < b.id ? -1 : 1));
  const body = { schema: PLAN_SCHEMA, schemaVersion: '1.0.0', ...(synthetic ? { synthetic: true } : {}), units, rejected: rejected.sort((a, b) => (a.repository < b.repository ? -1 : 1)) };
  return { ok: errors.length === 0, errors, plan: errors.length === 0 ? { ...body, id: `pplan:${digestOf(units).slice(7, 23)}` } : null };
}

// ---------------------------------------------------------------- state

const eventDigest = (e) => (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)(e);

function appendEvent(unit, ev) {
  if (unit.events.length >= PORTFOLIO_LIMITS.maxEventsPerUnit) throw typedError('EVENT_LIMIT', `unit ${unit.id} reached ${PORTFOLIO_LIMITS.maxEventsPerUnit} recorded events`);
  const prev = unit.events.length ? unit.events[unit.events.length - 1].digest : null;
  const body = { seq: unit.events.length + 1, prev, ...ev };
  unit.events.push({ ...body, digest: eventDigest(body) });
}

function typedError(code, message, extra = {}) { return Object.assign(new Error(message), { code, ...extra }); }

/** A new, empty store for a plan. */
function newStore(plan) {
  if (!plan || plan.schema !== PLAN_SCHEMA) throw typedError('BAD_PLAN', 'not a portfolio plan');
  const units = {};
  for (const u of plan.units) {
    units[u.id] = { ...u, state: 'pending', retryCount: 0, maxRetries: PORTFOLIO_LIMITS.defaultMaxRetries, generation: 0, attemptSeq: 0, lease: null, result: null, stale: [], blockedReason: null, events: [] };
  }
  return { schema: STORE_SCHEMA, version: STORE_VERSION, planId: plan.id, ...(plan.synthetic ? { synthetic: true } : {}), units };
}

/** Verify the store's internal consistency: event chains, state/lease/result agreement. Returns `{ ok, errors }`. */
function verifyStore(store) {
  const errors = [];
  if (!store || store.schema !== STORE_SCHEMA || store.version !== STORE_VERSION || typeof store.units !== 'object' || !store.units) return { ok: false, errors: [{ code: 'BAD_STORE', message: 'not a portfolio store of a supported version' }] };
  for (const [id, u] of Object.entries(store.units)) {
    if (u.id !== id || unitIdOf(u) !== id) errors.push({ code: 'ID_MISMATCH', unit: id, message: 'unit identity does not match its repository, commit, task type and inputs' });
    if (!UNIT_STATES.includes(u.state)) errors.push({ code: 'BAD_STATE', unit: id, message: `unknown state '${u.state}'` });
    let prev = null;
    (u.events ?? []).forEach((e, i) => {
      const { digest, ...body } = e;
      if (e.seq !== i + 1 || e.prev !== prev || eventDigest(body) !== digest) errors.push({ code: 'EVENT_CHAIN_BROKEN', unit: id, message: `event ${i + 1} was altered or removed` });
      prev = digest;
    });
    if ((u.state === 'leased' || u.state === 'running') !== !!u.lease) errors.push({ code: 'LEASE_STATE_MISMATCH', unit: id, message: 'a lease exists exactly when the unit is leased or running' });
    if (u.state === 'verified' && !(u.result && DIGEST_RE.test(u.result.resultDigest ?? ''))) errors.push({ code: 'VERIFIED_WITHOUT_RESULT', unit: id, message: 'a verified unit must carry a result digest' });
    if (u.state !== 'verified' && u.result) errors.push({ code: 'RESULT_WITHOUT_VERIFIED', unit: id, message: 'only a verified unit may carry a current result' });
  }
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------- transitions (pure on a store object)

const unitOf = (store, id) => {
  const u = store.units[id];
  if (!u) throw typedError('UNKNOWN_UNIT', `no such unit '${id}'`);
  return u;
};

function clampLease(ttlMs) {
  const t = ttlMs ?? PORTFOLIO_LIMITS.defaultLeaseMs;
  if (!Number.isFinite(t) || t < 1) throw typedError('BAD_LEASE', 'lease duration must be a positive number of milliseconds');
  return Math.min(t, PORTFOLIO_LIMITS.maxLeaseMs);
}

function spendAttempt(u, ev, now) {
  // an attempt ended without a verified result: it costs a retry. Out of retries is a terminal failure.
  u.lease = null;
  u.retryCount += 1;
  appendEvent(u, { ...ev, at: now });
  u.state = u.retryCount > u.maxRetries ? 'failed' : 'pending';
}

/** Recover every unit whose lease has expired. Returns the ids recovered. */
function recoverExpired(store, now) {
  const out = [];
  for (const id of Object.keys(store.units).sort()) {
    const u = store.units[id];
    if ((u.state === 'leased' || u.state === 'running') && u.lease && u.lease.expiresAt <= now) {
      const attemptId = u.lease.attemptId;
      spendAttempt(u, { type: 'expired', attemptId, holder: u.lease.holder }, now);
      out.push(id);
    }
  }
  return out;
}

/**
 * Lease the next pending unit (or a named one) to `holder`. A repeat of the same `requestId` from the same holder returns the same lease
 * instead of leasing a second unit (duplicate delivery of the request). Returns `null` when nothing is leasable.
 */
function leaseUnit(store, { holder, now, ttlMs, unitId = null, requestId = null, skip = () => false }) {
  if (typeof holder !== 'string' || !holder) throw typedError('BAD_HOLDER', 'a lease needs a holder');
  recoverExpired(store, now);
  if (requestId) {
    for (const u of Object.values(store.units)) {
      if (u.lease && u.lease.requestId === requestId && u.lease.holder === holder) return { unitId: u.id, attemptId: u.lease.attemptId, expiresAt: u.lease.expiresAt, duplicate: true };
    }
  }
  const candidates = unitId ? [unitOf(store, unitId)] : Object.values(store.units).sort((a, b) => (a.id < b.id ? -1 : 1));
  const u = candidates.find((c) => c.state === 'pending' && !skip(c));
  if (!u) return null;
  u.attemptSeq += 1;
  const attemptId = `${u.id}#${u.generation}.${u.attemptSeq}`;
  const expiresAt = now + clampLease(ttlMs);
  u.lease = { holder, attemptId, expiresAt, requestId };
  u.state = 'leased';
  appendEvent(u, { type: 'leased', attemptId, holder, at: now, expiresAt });
  return { unitId: u.id, attemptId, expiresAt, duplicate: false };
}

function liveAttempt(store, unitId, attemptId, now) {
  recoverExpired(store, now);
  const u = unitOf(store, unitId);
  if (!u.lease || u.lease.attemptId !== attemptId) return { u, ok: false };
  return { u, ok: true };
}

/** leased -> running. Idempotent for the same attempt. */
function startUnit(store, { unitId, attemptId, now }) {
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease (it expired, or the unit moved on)' };
  if (u.state === 'running') return { ok: true, duplicate: true };
  u.state = 'running';
  appendEvent(u, { type: 'started', attemptId, at: now });
  return { ok: true, duplicate: false };
}

/** Extend a live lease. */
function renewLease(store, { unitId, attemptId, now, ttlMs }) {
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'the lease is no longer held' };
  u.lease.expiresAt = now + clampLease(ttlMs);
  appendEvent(u, { type: 'renewed', attemptId, at: now, expiresAt: u.lease.expiresAt });
  return { ok: true, expiresAt: u.lease.expiresAt };
}

/** A recorded result's dependency digests, one per dimension. All six are required: a result without them cannot be reused. */
function checkDependencies(deps) {
  const missing = DEPENDENCY_DIMENSIONS.filter((d) => !DIGEST_RE.test(deps?.[d] ?? ''));
  return missing;
}

/**
 * Record a verified result. Accepted only from the live attempt, with all six dependency digests. A second delivery of the same
 * completion is acknowledged and changes nothing; a completion from a stale attempt is refused.
 */
function completeUnit(store, { unitId, attemptId, resultDigest, dependencies, now }) {
  const u0 = unitOf(store, unitId);
  if (u0.state === 'verified' && u0.result?.attemptId === attemptId) return { ok: true, duplicate: true, counted: false };
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease (it expired, or the unit moved on); the result is discarded' };
  if (!DIGEST_RE.test(resultDigest ?? '')) return { ok: false, code: 'bad-result', reason: 'a result needs a sha256 digest' };
  const missing = checkDependencies(dependencies);
  if (missing.length) return { ok: false, code: 'unbound-dependencies', reason: `result is missing dependency digests: ${missing.join(', ')}` };
  const deps = Object.fromEntries(DEPENDENCY_DIMENSIONS.map((d) => [d, dependencies[d]]));
  u.lease = null;
  u.result = { attemptId, resultDigest, dependencies: deps, dependencyDigest: digestOf(deps), generation: u.generation };
  u.state = 'verified';
  appendEvent(u, { type: 'verified', attemptId, at: now, resultDigest, dependencyDigest: u.result.dependencyDigest });
  return { ok: true, duplicate: false, counted: true };
}

/** The live attempt ended in failure. Costs a retry; out of retries the unit is terminally `failed`. */
function failUnit(store, { unitId, attemptId, reason, now }) {
  const u0 = unitOf(store, unitId);
  const dup = u0.events.some((e) => e.type === 'failed' && e.attemptId === attemptId);
  if (dup) return { ok: true, duplicate: true };
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease' };
  spendAttempt(u, { type: 'failed', attemptId, holder: u.lease?.holder ?? null, reason: String(reason ?? 'failed').slice(0, 300) }, now);
  return { ok: true, duplicate: false, state: u.state };
}

/** Park a unit that cannot proceed (a missing input). Not counted; independent units still run. */
function blockUnit(store, { unitId, reason, now }) {
  const u = unitOf(store, unitId);
  if (!['pending', 'leased', 'running'].includes(u.state)) return { ok: false, code: 'bad-state', reason: `cannot block a ${u.state} unit` };
  u.lease = null; u.state = 'blocked'; u.blockedReason = String(reason ?? 'blocked').slice(0, 300);
  appendEvent(u, { type: 'blocked', reason: u.blockedReason, at: now });
  return { ok: true };
}

function unblockUnit(store, { unitId, now }) {
  const u = unitOf(store, unitId);
  if (u.state !== 'blocked') return { ok: false, code: 'bad-state', reason: `unit is ${u.state}, not blocked` };
  u.state = 'pending'; u.blockedReason = null;
  appendEvent(u, { type: 'unblocked', at: now });
  return { ok: true };
}

/** Cancel every unit that is not verified or terminally failed (or one named unit). Leases are released; verified receipts and failure records are kept. */
function cancelUnits(store, { unitId = null, reason, now }) {
  const canceled = [];
  for (const id of Object.keys(store.units).sort()) {
    if (unitId && id !== unitId) continue;
    const u = store.units[id];
    if (u.state === 'verified' || u.state === 'canceled' || u.state === 'failed') continue; // receipts and terminal failures keep their own status
    u.lease = null; u.state = 'canceled';
    appendEvent(u, { type: 'canceled', reason: String(reason ?? 'canceled').slice(0, 300), at: now });
    canceled.push(id);
  }
  return { ok: true, canceled };
}

// ---------------------------------------------------------------- progress

/** Counts by state. `verified` is the only count that is progress. */
function progressOf(store) {
  const by = Object.fromEntries(UNIT_STATES.map((s) => [s, 0]));
  let staleResults = 0;
  for (const u of Object.values(store.units)) { by[u.state] += 1; staleResults += u.stale.length; }
  const total = Object.keys(store.units).length;
  return { total, ...by, completed: by.verified, remaining: total - by.verified - by.canceled, staleResults, done: total > 0 && by.verified === total };
}

/** The current scoped results: verified units only, keyed by unit id. Two runs converged exactly when these are equal. */
function scopedResults(store) {
  return Object.fromEntries(Object.values(store.units).filter((u) => u.state === 'verified').sort((a, b) => (a.id < b.id ? -1 : 1)).map((u) => [u.id, u.result.resultDigest]));
}

/** Repositories whose every unit is verified and current: what `runFleet({ portfolioVerified })` may skip. */
function fullyVerifiedRepositories(store) {
  const by = new Map();
  for (const u of Object.values(store.units)) by.set(u.repository, (by.get(u.repository) ?? true) && u.state === 'verified');
  return [...by].filter(([, ok]) => ok).map(([r]) => r).sort();
}

// ---------------------------------------------------------------- persistence

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(file, fn) {
  const lock = `${file}.lock`;
  const start = Date.now();
  for (;;) {
    try { fs.writeFileSync(lock, String(process.pid), { flag: 'wx' }); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > PORTFOLIO_LIMITS.lockStaleMs) { fs.unlinkSync(lock); continue; } } catch { continue; }
      if (Date.now() - start > PORTFOLIO_LIMITS.lockWaitMs) throw typedError('LOCK_TIMEOUT', 'could not take the portfolio store lock');
      sleepSync(5);
    }
  }
  try { return fn(); } finally { try { fs.unlinkSync(lock); } catch { /* already gone */ } }
}

/** Read and verify a store. Throws `STORE_CORRUPT` rather than returning a guess. */
function readStore(file) {
  let raw;
  try {
    const st = node_fs__WEBPACK_IMPORTED_MODULE_1__.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > PORTFOLIO_LIMITS.maxStoreBytes) throw typedError('STORE_CORRUPT', 'store is not a regular file within the size limit');
    raw = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(file, 'utf8');
  } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  let store;
  try { store = JSON.parse(raw); } catch { throw typedError('STORE_CORRUPT', 'store is not valid JSON'); }
  const v = verifyStore(store);
  if (!v.ok) throw typedError('STORE_CORRUPT', `store failed verification: ${v.errors[0].code} ${v.errors[0].unit ?? ''}`, { errors: v.errors });
  return store;
}

function writeStore(file, store) {
  const text = JSON.stringify(store);
  if (text.length > PORTFOLIO_LIMITS.maxStoreBytes) throw typedError('STORE_TOO_LARGE', 'store would exceed the size limit');
  const tmp = `${file}.tmp-${process.pid}`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/**
 * Open (or create) the durable store for a plan. An existing store for a DIFFERENT plan is an error: resuming the wrong portfolio would
 * silently mix two sets of results.
 */
function openStore(file, plan) {
  return withLock(file, () => {
    const existing = readStore(file);
    if (existing) {
      if (existing.planId !== plan.id) throw typedError('PLAN_MISMATCH', `the store at this path belongs to plan ${existing.planId}, not ${plan.id}`);
      return existing;
    }
    const fresh = newStore(plan);
    writeStore(file, fresh);
    return fresh;
  });
}

/** Locked read-modify-write. `fn(store)` mutates and returns a value; the store is verified before it is written back. */
function mutateStore(file, fn) {
  return withLock(file, () => {
    const store = readStore(file);
    if (!store) throw typedError('NO_STORE', 'no portfolio store at this path');
    const out = fn(store);
    const v = verifyStore(store);
    if (!v.ok) throw typedError('STORE_CORRUPT', `refusing to write a store that fails verification: ${v.errors[0].code}`, { errors: v.errors });
    writeStore(file, store);
    return out;
  });
}

// ---------------------------------------------------------------- runner

/**
 * Drive a store to completion with bounded concurrency. Mirrors runFleet's isolation: an executor that throws FAILS its unit (and costs
 * a retry), it never takes the run down. `executor(unit, ctx)` returns `{ resultDigest, dependencies }`.
 *
 * `maxUnits` stops after that many units have been leased, for interruption tests and for time-boxed runs. Returns the progress.
 */
async function runPortfolio({ file, executor, holder = 'worker', clock = () => Date.now(), ttlMs, concurrency = 2, maxUnits = Infinity, skip = () => false }) {
  let leased = 0;
  const limit = Math.max(1, Math.min(concurrency, 16));
  async function worker(n) {
    for (;;) {
      if (leased >= maxUnits) return;
      const lease = mutateStore(file, (s) => leaseUnit(s, { holder: `${holder}-${n}`, now: clock(), ttlMs, skip }));
      if (!lease) return;
      leased += 1;
      mutateStore(file, (s) => startUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, now: clock() }));
      const unit = readStore(file).units[lease.unitId];
      let res = null; let err = null;
      try { res = await executor(unit, { attemptId: lease.attemptId }); } catch (e) { err = e; }
      mutateStore(file, (s) => {
        if (err || !res) failUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, reason: err ? err.message : 'executor returned nothing', now: clock() });
        else completeUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, resultDigest: res.resultDigest, dependencies: res.dependencies, now: clock() });
      });
    }
  }
  await Promise.all(Array.from({ length: limit }, (_, i) => worker(i)));
  return progressOf(readStore(file));
}


/***/ })

};
