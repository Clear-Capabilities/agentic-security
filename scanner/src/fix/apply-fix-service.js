// ApplyFixService (assurance-hardening PRD, FR-301/FR-302/FR-303/FR-304).
//
// Before this module, three write paths each re-implemented (or partly
// skipped) the same safety checks:
//
//   - mcp/tools.js's apply_fix, caller-patch branch: confines paths, checks
//     reserved-write paths, fails closed on bad last-scan.json integrity,
//     and runs a fresh verifyFixCore before writing. The strongest of the
//     three, and the model this module generalizes.
//   - mcp/tools.js's apply_fix, stored-fix.replacement branch: confines
//     paths and checks reserved-write paths, but WRITES WITHOUT any fresh
//     verification (no rescan, no lint check) — verified missing by reading
//     the handler directly (A-08).
//   - bin/agentic-security.js's `cmdFix --apply`: WARNS (does not refuse) on
//     failed last-scan.json integrity, has NO path confinement check at all
//     (a relative path with `../../` or a pre-planted symlink is followed
//     without question), and applies WITHOUT any fresh verification. This
//     was a materially worse gap than FR-301's PRD evidence table (A-08)
//     described — A-08 only flagged the missing verification, not the
//     missing confinement or the fail-open integrity check.
//
// This module is the one place all of that lives now. It does NOT
// reimplement the transactional write itself — posture/fix-history.js's
// applyFix() already does backup+fsync, pending-log+fsync,
// write+fsync, promote-to-applied+fsync, with its own crash-recovery
// (`recover()`) and per-finding attempt-budget enforcement. That machinery
// was already sound and already shared; the gap was upstream of it.
//
// Confinement and reserved-write-path logic is copied verbatim from
// mcp/tools.js's `_confine`/`_isReservedWritePath` (not rewritten) so
// behavior does not drift between the two callers during migration —
// mcp/tools.js still owns its own copies for its scratchpad/other tools
// that need the same primitives without the full apply-fix flow; a future
// cleanup could have it import from here instead, out of scope for this
// change.

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { verifyLastScan } from '../posture/integrity.js';
import { stateDir } from '../posture/state-dir.js';
import { applyFix as applyFixHistory, revertEntryById as revertFixEntry } from '../posture/fix-history.js';
import { classifyFixMaterialRisk } from '../posture/material-change.js';
import { loadApproverRegistry, verifyApprover, requiredRolesFor, checkSeparationOfDuties } from './approver-registry.js';

const RESERVED_WRITE_PREFIXES = [
  '.git/', '.github/', '.gitlab/', '.circleci/', '.buildkite/',
  '.agentic-security/', 'node_modules/', '.terraform/', '.aws/', 'k8s/', 'kubernetes/',
];
const RESERVED_WRITE_BASENAMES = new Set([
  'Dockerfile', 'Jenkinsfile', '.gitlab-ci.yml', '.gitlab-ci.yaml',
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'requirements.txt',
  'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'composer.json', 'composer.lock',
  'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
]);
const RESERVED_WRITE_SUFFIXES = ['.tf', '.tfvars', 'docker-compose.yml', 'docker-compose.yaml', '.bak', '.lock'];
const RESERVED_WRITE_DIR_SEGMENTS = new Set(['dist', 'build', 'target']);

/** Lexical check + lstat symlink reject + realpath re-check. OWASP MCP05. */
export function confinePath(root, candidate, label = 'path') {
  if (typeof candidate !== 'string' || !candidate) throw new Error(`${label}: not a string`);
  const rootReal = fs.realpathSync(path.resolve(root));
  const abs = path.isAbsolute(candidate) ? candidate : path.resolve(rootReal, candidate);

  const relLex = path.relative(rootReal, path.resolve(abs));
  if (relLex === '' || relLex.startsWith('..') || path.isAbsolute(relLex)) {
    throw new Error(`${label}: path "${candidate}" escapes session root`);
  }

  if (fs.existsSync(abs)) {
    if (fs.lstatSync(abs).isSymbolicLink()) {
      throw new Error(`${label}: path "${candidate}" is a symbolic link (refused)`);
    }
    const real = fs.realpathSync(abs);
    if (path.relative(rootReal, real).startsWith('..')) {
      throw new Error(`${label}: path "${candidate}" resolves outside session root via symlink`);
    }
    return real;
  }

  let parent = path.dirname(abs);
  while (parent !== path.dirname(parent) && !fs.existsSync(parent)) {
    parent = path.dirname(parent);
  }
  const parentReal = fs.realpathSync(parent);
  if (path.relative(rootReal, parentReal).startsWith('..')) {
    throw new Error(`${label}: path "${candidate}" parent resolves outside session root`);
  }
  return path.resolve(parentReal, path.relative(parent, abs));
}

export function isReservedWritePath(root, absFile) {
  const rootReal = fs.realpathSync(path.resolve(root));
  const rel = path.relative(rootReal, absFile).replace(/\\/g, '/');
  if (RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p))) return true;
  const segments = rel.split('/');
  const base = segments[segments.length - 1] || '';
  if (RESERVED_WRITE_BASENAMES.has(base)) return true;
  if (RESERVED_WRITE_SUFFIXES.some(s => base === s || base.endsWith(s))) return true;
  if (segments.slice(0, -1).some(seg => RESERVED_WRITE_DIR_SEGMENTS.has(seg))) return true;
  return false;
}

/** SHA-256 of a file's current content, or null if it does not exist. Shared by
 * both the pre-verification baseline snapshot and the pre-write recheck below,
 * so the two can never disagree about what "unchanged" means. Read first,
 * classify ENOENT as "does not exist" — the same existsSync-then-readFileSync
 * TOCTOU this codebase has already fixed twice this session (readVerifiedScan
 * here, egress/policy.js's loadPolicyConfig) applies equally to this new
 * function, so it uses the same read-first pattern from the start. */
export function hashFileContentSync(absPath) {
  let body;
  try {
    body = fs.readFileSync(absPath, 'utf8');
  } catch (e) {
    if (e && e.code === 'ENOENT') return null;
    throw e;
  }
  return crypto.createHash('sha256').update(body).digest('hex');
}

/**
 * FR-304: does any file in `confined` (a map of rel -> {abs, baselineHash})
 * no longer match the hash captured before verification started? Returns the
 * first mismatched rel path's reason string, or null if every file still
 * matches its baseline. A pure, synchronous, directly-testable check — no
 * verification timing involved — so this exact race-window property can be
 * proven deterministically instead of by racing real wall-clock verification
 * time (which varies 10x+ between runs and under combined-suite load, the
 * same contention class as this codebase's own documented D-0006 flake).
 */
export function detectConcurrentModification(confined) {
  for (const [rel, v] of Object.entries(confined)) {
    if (hashFileContentSync(v.abs) !== v.baselineHash) {
      return `${rel} changed on disk after verification started — a stale approval must not be applied to a moved target. Re-run verification against the current file.`;
    }
  }
  return null;
}

/**
 * Fail-closed read of last-scan.json. Unlike bin/agentic-security.js's old
 * behavior (log a warning, apply anyway), a caller that does not explicitly
 * pass `allowUnsigned: true` gets `{scan: null}` on any integrity problem —
 * missing, tampered, or unsigned — and MUST refuse the write.
 */
export function readVerifiedScan(scanRoot, { allowUnsigned = false } = {}) {
  const scanFile = path.join(stateDir(scanRoot), 'last-scan.json');
  const sigFile = scanFile + '.sig';
  // Self-scan gate (bench/self-scan): a check-then-read (existsSync then
  // readFileSync) is a TOCTOU — the file can vanish between the two calls
  // (a concurrent `reset`, another process). Read first and classify ENOENT
  // as 'missing'; any other read error still propagates, same as before.
  let body;
  try {
    body = fs.readFileSync(scanFile, 'utf8');
  } catch (e) {
    if (e && e.code === 'ENOENT') return { scan: null, status: 'missing' };
    throw e;
  }
  const ok = verifyLastScan(body, sigFile);
  if (ok === false) return { scan: null, status: 'tampered' };
  if (ok === null && !allowUnsigned) return { scan: null, status: 'unsigned' };
  let parsed;
  try { parsed = JSON.parse(body); } catch { return { scan: null, status: 'unparseable' }; }
  return { scan: parsed, status: ok ? 'verified' : 'unsigned' };
}

let _verifyFixCore;
async function getVerifyFixCore() {
  if (!_verifyFixCore) _verifyFixCore = (await import('../posture/fix-verify.js')).verifyFix;
  return _verifyFixCore;
}

/**
 * The unified apply flow. Every public entry point (MCP's two apply_fix
 * branches, the CLI's `--apply`) should reach a disk write only through
 * this function.
 *
 * @param {object} opts
 * @param {string} opts.scanRoot
 * @param {object} opts.finding - the finding being fixed (needs .file, .stableId, .id/.findingId)
 * @param {Record<string,string>} opts.files - { relPath: newContent } — one or more candidate files
 * @param {object} [opts.fixMeta] - optional agent-reported completeness/residual claims (fix-honesty-gate).
 *   FR-307: `fixMeta.approval` — `{approvedBy: string, reason: string}` — REQUIRED (else refused)
 *   when the candidate falls into a high-impact change class (auth/authZ/crypto/pii/schema/
 *   infra-privilege/public-api, per posture/material-change.js's classifyFixMaterialRisk). Absent
 *   for every other candidate, which is unaffected by this check. FR-1002: when
 *   .agentic-security/authorized-approvers.json is configured, `approvedBy` is ALSO checked
 *   against it (fix/approver-registry.js) — an approvedBy the registry doesn't recognize, or one
 *   missing a role a touched category requires, is refused. A no-op with no registry configured.
 * @param {boolean} [opts.dryRun]
 * @param {boolean} [opts.skipVerification] - escape hatch for callers that have ALREADY verified
 *   (none currently use this — present so a future caller cannot be forced into double verification
 *   cost without a documented way to opt out; using it without having independently verified defeats
 *   the entire point of this service).
 * @returns {Promise<{ok:boolean, applied:boolean, reason?:string, verify?:object, written?:object[],
 *   verified?:boolean, verifiedFull?:boolean, materialClassification?:object}>} `verified` means
 *   verification was attempted (and passed, when true); `verifiedFull` (FR-305) means every required leg — lint when a linter is
 *   configured, tests when a runner is detected — genuinely ran and passed, not silently skipped.
 *   `verified:true, verifiedFull:false` is a real, honest state: applied, but on a degraded pass.
 */
export async function applyVerifiedFix({ scanRoot, finding, files, fixMeta = null, dryRun = false, skipVerification = false } = {}) {
  if (!scanRoot) return { ok: false, applied: false, reason: 'scanRoot required' };
  if (!finding) return { ok: false, applied: false, reason: 'finding required' };
  if (!files || typeof files !== 'object' || !Object.keys(files).length) {
    return { ok: false, applied: false, reason: 'no candidate file content provided' };
  }

  // FR-302: fail closed on invalid/missing signed scan-state integrity.
  // Both current callers (bin/agentic-security.js's cmdFix, mcp/tools.js's
  // apply_fix) already read+verify last-scan.json themselves before calling
  // here — they need the scan CONTENT to look up the finding in the first
  // place, not just a pass/fail signal, so this check is deliberately
  // redundant with theirs. It stays here anyway: a shared service that is
  // only safe because every CURRENT caller happens to check first is not
  // actually safe — it is safe by convention, which is exactly the failure
  // mode FR-301 was created to close for path confinement and verification.
  // A future caller that forgets its own pre-check is still refused here.
  const { status: integrityStatus } = readVerifiedScan(scanRoot);
  if (integrityStatus !== 'verified') {
    return { ok: false, applied: false, reason: `last-scan.json integrity check failed: ${integrityStatus}` };
  }

  const confined = {};
  for (const [rel, content] of Object.entries(files)) {
    let abs;
    try { abs = confinePath(scanRoot, rel, 'finding file'); }
    catch (e) { return { ok: false, applied: false, reason: `path-escape refused: ${e.message}` }; }
    if (isReservedWritePath(scanRoot, abs)) {
      return { ok: false, applied: false, reason: `reserved path refused: ${rel}` };
    }
    // FR-304: "a changed file invalidates approval". Verification below can
    // take real wall-clock time — verifyFixCore runs a rescan AND the
    // project's own lint/test legs, easily seconds. Snapshotting each file's
    // on-disk content NOW, before verification starts, and re-checking it
    // immediately before the write (below) closes the window where the file
    // changes between "this was approved" and "this gets written" — without
    // this, that drift is invisible and the write silently clobbers
    // whatever changed the file in between.
    let baselineHash = null;
    try {
      baselineHash = hashFileContentSync(abs);
    } catch (e) {
      return { ok: false, applied: false, reason: `could not read current content of ${rel} to detect concurrent changes: ${e.message}` };
    }
    confined[rel] = { abs, content: String(content), baselineHash };
  }

  // FR-303/FR-307: classify the candidate BEFORE verification (fail fast,
  // same reasoning FR-304's baseline-hash check already applies — no point
  // running a real rescan+lint+test verification pass on a change that is
  // refused regardless of its outcome). "Auth, authZ, crypto, PII, schema,
  // infrastructure privilege, and public API changes cannot auto-apply
  // without approval evidence" — a no-op for every OTHER candidate (the
  // overwhelming majority of fixes), matching this codebase's
  // restricts-nothing-until-triggered convention for every other policy
  // gate (egress/policy.js, dataflow/privacy-sink-policy.js).
  const filesForMaterialClassification = {};
  for (const [rel, v] of Object.entries(confined)) {
    let before = '';
    try { before = fs.existsSync(v.abs) ? await fsp.readFile(v.abs, 'utf8') : ''; } catch { /* new file — before stays '' */ }
    filesForMaterialClassification[rel] = { before, after: v.content };
  }
  const materialClassification = classifyFixMaterialRisk(filesForMaterialClassification);
  // A dry run never writes anything (`applied` is always false below), so it
  // is allowed to preview past this gate WITHOUT approval evidence — an
  // agent needs exactly that preview to learn a real apply will need
  // approval before it goes and collects it. `materialClassification` is
  // still attached to every return path below so the gap is never silent.
  if (materialClassification.highImpactCategories.length && !dryRun) {
    const approval = fixMeta && typeof fixMeta === 'object' ? fixMeta.approval : null;
    const hasApprovalEvidence = !!(approval && typeof approval === 'object' &&
      typeof approval.approvedBy === 'string' && approval.approvedBy.trim().length > 0 &&
      typeof approval.reason === 'string' && approval.reason.trim().length > 0);
    if (!hasApprovalEvidence) {
      return {
        ok: false, applied: false,
        reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) requires approval evidence — pass fixMeta.approval: {approvedBy, reason} — before it can be applied`,
        materialClassification,
      };
    }
    // FR-1002: bind the approval to a verified (operator-registered)
    // identity and role, when an operator has opted in via
    // .agentic-security/authorized-approvers.json. A no-op with no
    // registry configured — approvedBy's mere presence (checked above)
    // remains sufficient, unchanged from FR-307's own behavior. With a
    // registry present, an approvedBy the registry doesn't recognize, or
    // one recognized but missing a role a touched category requires, is
    // refused: the literal "anonymous or unauthorized... fail policy"
    // acceptance criterion.
    const approverRegistry = loadApproverRegistry(scanRoot);
    const requiredRoles = requiredRolesFor(approverRegistry, materialClassification.highImpactCategories);
    const identityCheck = verifyApprover(approverRegistry, approval.approvedBy, requiredRoles);
    if (!identityCheck.verified) {
      return {
        ok: false, applied: false,
        reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${identityCheck.reason}`,
        materialClassification,
      };
    }
    // FR-1003: "a configurable policy can prevent the patch author from
    // self-approving a high-impact fix." A no-op unless the SAME registry
    // opts in via `separationOfDuties.enabled` — an operator who has not
    // configured this is unaffected, matching every other dimension here.
    const sodCheck = checkSeparationOfDuties(approverRegistry, fixMeta?.author, approval.approvedBy);
    if (!sodCheck.ok) {
      return {
        ok: false, applied: false,
        reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${sodCheck.reason}`,
        materialClassification,
      };
    }
  }

  let verify = null;
  if (!skipVerification) {
    if (!finding.stableId) {
      return { ok: false, applied: false, reason: 'finding has no stableId — cannot verify a candidate fix against it' };
    }
    let verdict;
    try {
      const verifyFixCore = await getVerifyFixCore();
      verdict = await verifyFixCore({
        scanRoot,
        originalFindingStableId: finding.stableId,
        files: Object.fromEntries(Object.entries(confined).map(([rel, v]) => [rel, v.content])),
        fixMeta,
      });
    } catch (e) {
      return { ok: false, applied: false, reason: `verification failed: ${e.message}` };
    }
    verify = verdict;
    if (!verdict.ok) {
      return {
        ok: false, applied: false,
        reason: `rejected by verifier: ${verdict.summary || verdict.rescan?.reason || 'did not verify'}`,
        verify: { rescan: verdict.rescan, lint: verdict.lint ? { runner: verdict.lint.runner, ok: verdict.lint.ok } : null, honesty: verdict.honesty || null },
      };
    }
  }

  if (dryRun) {
    return { ok: true, applied: false, dryRun: true, verified: !skipVerification, files: Object.keys(confined), verify, materialClassification };
  }

  // FR-304: re-check every file against its pre-verification baseline hash,
  // ALL of them before writing ANY of them — a stale approval on file A must
  // not let file B (also stale) get partially written before the drift on B
  // is even checked.
  const concurrentChangeReason = detectConcurrentModification(confined);
  if (concurrentChangeReason) {
    return { ok: false, applied: false, reason: concurrentChangeReason };
  }

  const written = [];
  try {
    for (const [rel, v] of Object.entries(confined)) {
      const fileExisted = fs.existsSync(v.abs);
      const originalContent = fileExisted ? await fsp.readFile(v.abs, 'utf8') : '';
      const entry = await applyFixHistory({
        scanRoot, file: rel, originalContent, newContent: v.content, fileExisted,
        findingId: finding.id || finding.findingId,
        stableId: finding.stableId || null,
        ruleId: finding.ruleId || finding.cwe || finding.family || null,
        vuln: finding.vuln || finding.title || null,
        findingProvenance: finding.findingProvenance || null,
      });
      written.push({ file: rel, historyId: entry.id, backupPath: entry.backupPath, attemptOrdinal: entry.attemptOrdinal });
    }
  } catch (e) {
    // FR-306: "injected write failure restores all files" — applyFixHistory
    // already rolled back the ONE file that just failed; this rolls back
    // every file THIS batch had already successfully written before that
    // failure, so a multi-file fix never leaves some files patched and
    // others not. Best-effort per file — a revert failure here is recorded
    // on the entry itself (fix-history.js) and does not mask the original
    // error, which is what the caller actually needs to see.
    for (const w of written) {
      try { await revertFixEntry(scanRoot, w.historyId); } catch { /* best-effort; original error still propagates below */ }
    }
    if (e && e.name === 'FixAttemptBudgetExceededError') {
      return { ok: false, applied: false, reason: `budget-exceeded: ${e.message}`, budgetExceeded: true, attempts: e.attempts, maxAttempts: e.max, key: e.key };
    }
    throw e;
  }

  // FR-305: `verified: true` only ever meant "verification was attempted",
  // not "every required leg genuinely ran and passed" — a caller that
  // reported `verified` as "fully verified" would misrepresent a degraded
  // pass (e.g. no linter installed, no test runner detected) as a complete
  // one. `verifiedFull` is the honest, explicit answer to that question;
  // `false` when verification was skipped entirely (skipVerification:true)
  // just as much as when a required leg was skipped.
  return {
    ok: true, applied: true, verified: !skipVerification,
    verifiedFull: !skipVerification && verify ? !!verify.verifiedFull : false,
    written,
    verify: verify ? { summary: verify.summary, verifiedFull: verify.verifiedFull, degradedLegs: verify.degradedLegs || [] } : null,
    materialClassification,
  };
}
