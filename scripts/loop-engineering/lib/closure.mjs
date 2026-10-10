// Protected final closure (REL-003). The generic final phase (final.mjs) answers "did every criterion and gate pass on one stable
// tree". Closure answers the stricter release question for a profile that sets finalVerification.closure:
//
//   AC01  the OTHER requirements' receipts are validated first (fresh, issued by the controller in this final phase, signed, every
//         criterion a pass), then the closure requirement's own criteria are executed on the same stable tree, then ONE record is
//         issued atomically. Closed means every expected requirement and every expected criterion, not "no failure seen".
//   AC02  beyond per-requirement tests: DAG consistency, evidence-file hashes (checked again at issuance), quality / routing / release
//         gates by name, measured gates (a synthetic or insufficient population is never a pass), supported scope and controller limits.
//   AC03  deliverables: implementation diff, updated ledger, measured scorecards, policy cards, replayable fixtures and the release
//         assurance bundle. A gate that cannot be measured here stays OPEN and is listed as open; it is never turned into completion.
//
// Everything that decides is a pure function of facts (evaluateClosure and the check* helpers); the controller only gathers facts.
// A fact that cannot be gathered is a missing fact, and a missing fact is an unmet item, never a skip.
import { readFileSync, statSync, mkdirSync } from 'node:fs';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { execBoundedSync } from './bounds.mjs';
import { sha256, atomicWriteJson, atomicWriteFile, canonicalJson } from './util.mjs';
import { listEvidence, assessOne } from './evidence.mjs';
import { GATE_GROUPS, DELIVERABLE_KINDS } from './closure-config.mjs';

export const CLOSURE_SCHEMA = 1;
export { GATE_GROUPS, DELIVERABLE_KINDS };
const MAX_DIFF_BYTES = 64 * 1024 * 1024;

// ------------------------------------------------------------------ pure checks

const AC_RE = (id) => new RegExp(`^${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.AC(\\d{2,})$`);

/** DAG consistency of the frozen manifest. -> unmet[] */
export function checkDag(manifest, expect = null) {
  const unmet = [];
  const add = (id, reason) => unmet.push({ kind: 'dag', id, reason });
  const reqs = manifest.requirements || [];
  const ids = new Set();
  for (const r of reqs) { if (ids.has(r.id)) add(r.id, 'requirement id appears twice'); ids.add(r.id); }
  for (const r of reqs) {
    for (const d of r.dependencies || []) {
      if (d === r.id) add(r.id, 'depends on itself');
      else if (!ids.has(d)) add(r.id, `depends on ${d}, which is not a requirement of this manifest`);
    }
    const seq = (r.criteria || []).map((c) => c.id);
    seq.forEach((cid, i) => {
      const m = cid.match(AC_RE(r.id));
      if (!m || Number(m[1]) !== i + 1) add(r.id, `criterion id ${cid} is not ${r.id}.AC${String(i + 1).padStart(2, '0')} (ids must be sequential and belong to their requirement)`);
    });
    if (!(r.criteria || []).length) add(r.id, 'has no acceptance criteria');
    if (!Number.isInteger(r.weight) || r.weight < 1) add(r.id, 'weight must be a positive integer');
  }
  // cycle detection (Kahn): whatever cannot be ordered is on, or behind, a cycle
  const indeg = new Map(reqs.map((r) => [r.id, (r.dependencies || []).filter((d) => ids.has(d) && d !== r.id).length]));
  const queue = [...indeg].filter(([, n]) => n === 0).map(([id]) => id);
  let ordered = 0;
  while (queue.length) {
    const id = queue.shift(); ordered += 1;
    for (const r of reqs) if ((r.dependencies || []).includes(id) && r.id !== id) { indeg.set(r.id, indeg.get(r.id) - 1); if (indeg.get(r.id) === 0) queue.push(r.id); }
  }
  if (ordered < reqs.length) add('graph', `dependency cycle among: ${[...indeg].filter(([, n]) => n > 0).map(([id]) => id).join(', ')}`);
  const totals = {
    requirements: reqs.length, criteria: reqs.reduce((n, r) => n + (r.criteria || []).length, 0), weight: reqs.reduce((n, r) => n + (r.weight || 0), 0),
  };
  if (manifest.totals && (manifest.totals.requirements !== totals.requirements || manifest.totals.criteria !== totals.criteria || manifest.totals.weight !== totals.weight)) add('totals', 'the manifest totals disagree with its requirements');
  if (expect) {
    for (const k of ['requirements', 'criteria', 'weight']) if (totals[k] !== expect[k]) add('totals', `the manifest has ${totals[k]} ${k}; closure expects ${expect[k]}`);
  }
  return unmet;
}

/**
 * Receipt validation for the given requirement ids. A receipt counts only when it is: present; a valid signed envelope; fresh for the
 * tree; issued by the controller (never a worker-launched or operator verify); issued in THIS final phase; free of skipped tests; and
 * carries a pass for every criterion the manifest lists. -> { unmet[], passedCriteria }
 */
export function checkReceipts({ requirements, receipts, phaseStartedAt }) {
  const unmet = [];
  let passedCriteria = 0;
  const bad = new Set();
  const add = (kind, id, reason, owner) => { unmet.push({ kind, id, reason }); bad.add(owner); };
  for (const r of requirements) {
    const rc = receipts.get(r.id);
    if (!rc || !rc.found) { add('receipt-missing', r.id, 'no receipt exists for this requirement', r.id); continue; }
    if (!rc.valid) { add('receipt-invalid', r.id, `receipt ${rc.evidenceId} is not a valid signed envelope: ${(rc.invalidReasons || []).join('; ') || 'unspecified'}`, r.id); continue; }
    if (!rc.fresh) { add('receipt-stale', r.id, `receipt ${rc.evidenceId} is stale: ${(rc.staleReasons || []).join('; ') || 'inputs changed'}`, r.id); continue; }
    if (rc.invoker !== 'controller') { add('receipt-not-independent', r.id, `receipt ${rc.evidenceId} was issued by "${rc.invoker}", not by the controller`, r.id); continue; }
    if (rc.phase !== 'final' || !rc.createdAt || (phaseStartedAt && rc.createdAt < phaseStartedAt)) { add('receipt-not-fresh', r.id, `receipt ${rc.evidenceId} was not issued in this final phase (phase "${rc.phase}", ${rc.createdAt})`, r.id); continue; }
    if (rc.blockerType) { add('criterion-blocked', r.id, `required backend unavailable (${rc.blockerType}); a blocked criterion is never a pass`, r.id); continue; }
    if ((rc.counts?.skipped || 0) > 0) add('criterion-skipped', r.id, `${rc.counts.skipped} test(s) skipped; a skipped required test counts as failed`, r.id);
    if (rc.result !== 'pass') add('criterion-failed', r.id, `receipt result is ${rc.result}`, r.id);
    for (const c of r.criteria) {
      const got = (rc.criteria || []).find((x) => x.id === c.id);
      if (!got) { add('criterion-missing', c.id, `the receipt carries no result for ${c.id}`, r.id); continue; }
      // a passing criterion inside a receipt that is itself failed or skipped is not counted; the receipt-level item above names why
      if (got.state === 'pass') { if (rc.result === 'pass' && !(rc.counts?.skipped > 0)) passedCriteria += 1; continue; }
      const kind = { fail: 'criterion-failed', skipped: 'criterion-skipped', blocked: 'criterion-blocked', waived: 'criterion-waived', stale: 'criterion-stale' }[got.state] || 'criterion-invalid';
      add(kind, c.id, `${c.id} is ${got.state}${got.reason ? `: ${got.reason}` : ''}${got.state === 'waived' ? '; a mandatory criterion cannot be waived into completion' : ''}`, r.id);
    }
  }
  return { unmet, passedCriteria, badRequirements: bad };
}

/** Evidence-file hashes: the digest taken at validation must equal the digest at issuance, and logs must still match their recorded hashes. */
export function checkEvidenceHashes(receipts) {
  const unmet = [];
  for (const [id, rc] of receipts) {
    if (!rc.found) continue;
    if (rc.fileSha256 && rc.fileSha256AtIssue && rc.fileSha256 !== rc.fileSha256AtIssue) unmet.push({ kind: 'evidence-hash', id, reason: `evidence file ${rc.evidenceId} changed between validation and issuance` });
    if ((rc.logProblems || []).length) unmet.push({ kind: 'evidence-hash', id, reason: `log hash problem: ${rc.logProblems.join('; ')}` });
    if (!rc.fileSha256) unmet.push({ kind: 'evidence-hash', id, reason: 'the evidence file could not be hashed' });
  }
  return unmet;
}

/** Required gates by name and group. A gate that did not run is as unmet as one that failed. */
export function checkRequiredGates({ gates, requiredGates }) {
  const unmet = [];
  const by = new Map(gates.map((g) => [g.id, g]));
  for (const group of GATE_GROUPS) {
    for (const id of requiredGates?.[group] || []) {
      const g = by.get(id);
      if (!g) unmet.push({ kind: 'gate-missing', id, reason: `${group} gate did not run` });
      else if (!g.ok) unmet.push({ kind: 'gate-failed', id, reason: `${group} gate failed (exit ${g.exitCode ?? 'n/a'})` });
    }
  }
  return unmet;
}

/** Measured gates. Only a non-synthetic `pass` is measured. Anything else is OPEN: reported as open, never as completion. */
export function checkMeasured(measured) {
  const unmet = []; const open = [];
  for (const m of measured || []) {
    if (m.ran === false) { unmet.push({ kind: 'gate-missing', id: m.id, reason: `measured ${m.group} gate did not run: ${m.reason}` }); continue; }
    if (m.status === 'pass' && m.synthetic !== true) continue;
    open.push({ kind: 'open-gate', id: m.id, status: m.status || 'unmeasured', reason: m.synthetic === true ? `${m.group} gate reads ${m.status || 'unmeasured'} on a synthetic population; no adjudicated population exists, so it stays open` : (m.reason || `${m.group} gate status is ${m.status || 'unmeasured'}`) });
  }
  return { unmet, open };
}

/** Controller limits: the live profile equals the frozen one, stays inside the ceilings, and no budget is exhausted or run blocked. */
export function checkLimits({ profileLimits, frozenLimits, config, used, runBlockers = [] }) {
  const unmet = [];
  const add = (reason) => unmet.push({ kind: 'limits', id: 'controller-limits', reason });
  if (canonicalJson(profileLimits || null) !== canonicalJson(frozenLimits || null)) add('the profile limits changed since the manifest was frozen');
  const flat = (o, pre = '') => Object.entries(o || {}).flatMap(([k, v]) => (v && typeof v === 'object' ? flat(v, `${pre}${k}.`) : [[`${pre}${k}`, v]]));
  const at = (o, path) => path.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o);
  for (const [path, ceiling] of flat(config.max)) { const v = at(profileLimits, path); if (typeof v !== 'number') add(`limit ${path} is not set`); else if (v > ceiling) add(`limit ${path} is ${v}, above the ceiling ${ceiling}`); }
  for (const [path, floor] of flat(config.min)) { const v = at(profileLimits, path); if (typeof v !== 'number') add(`limit ${path} is not set`); else if (v < floor) add(`limit ${path} is ${v}, below the floor ${floor}`); }
  if (used) {
    if (used.attemptsUsed > profileLimits?.runMaxAttempts) add(`attempts used ${used.attemptsUsed} exceed runMaxAttempts ${profileLimits.runMaxAttempts}`);
    if (used.usdUsed > profileLimits?.claudeBudgetUsd) add(`spend ${used.usdUsed} exceeds claudeBudgetUsd ${profileLimits.claudeBudgetUsd}`);
    if (used.wallUsedMs > (profileLimits?.runWallSeconds || 0) * 1000) add(`wall time ${Math.round(used.wallUsedMs / 1000)}s exceeds runWallSeconds ${profileLimits.runWallSeconds}`);
  }
  if (runBlockers.length) add(`run-level blockers are present: ${runBlockers.map((b) => b.type).join(', ')}`);
  return unmet;
}

/** Supported scope: the platform is one the profile supports, and the scope documents exist. Unsupported platforms are named, not waived. */
export function checkScope({ platform, supported, unsupported, files }) {
  const unmet = [];
  if (!(supported || []).includes(platform)) unmet.push({ kind: 'scope', id: 'platform', reason: `platform ${platform} is not in the profile's supported platforms${(unsupported || []).includes(platform) ? ' (it is listed as unsupported)' : ''}` });
  for (const f of files || []) if (!f.present) unmet.push({ kind: 'scope', id: f.path, reason: 'supported-scope document is missing' });
  return unmet;
}

/** Deliverables: each must be present; one that is present but describes unmet work is OPEN, which also prevents closure. */
export function checkDeliverables(deliverables, kinds = DELIVERABLE_KINDS) {
  const unmet = []; const open = [];
  const by = new Map((deliverables || []).map((d) => [d.kind, d]));
  for (const kind of kinds) {
    const d = by.get(kind);
    if (!d || d.status === 'missing') unmet.push({ kind: 'deliverable-missing', id: kind, reason: d?.reason || 'deliverable was not produced' });
    else if (d.status === 'open') open.push({ kind: 'deliverable-open', id: kind, reason: d.reason || 'deliverable describes work that is still open' });
  }
  return { unmet, open };
}

const dedupe = (list) => { const seen = new Set(); return list.filter((u) => { const k = `${u.kind}\u0001${u.id}\u0001${u.reason}`; if (seen.has(k)) return false; seen.add(k); return true; }); };

/**
 * The closure decision. Pure. See the header for what each input is. Closed requires: no unmet item, no open item, and the verified
 * counts equal to the EXPECTED counts (not merely "everything we looked at passed").
 */
export function evaluateClosure(f) {
  const { config, manifest } = f;
  const unmet = [];
  const reqs = manifest.requirements;
  const rel = reqs.find((r) => r.id === config.releaseRequirement);
  if (!rel) unmet.push({ kind: 'dag', id: config.releaseRequirement, reason: 'the closure requirement is not in the manifest' });
  unmet.push(...checkDag(manifest, config.expect));

  const others = reqs.filter((r) => r.id !== config.releaseRequirement);
  const phase = f.order?.phaseStartedAt;
  const a = checkReceipts({ requirements: others, receipts: f.receipts, phaseStartedAt: phase });
  const b = rel ? checkReceipts({ requirements: [rel], receipts: f.receipts, phaseStartedAt: phase }) : { unmet: [], passedCriteria: 0, badRequirements: new Set() };
  unmet.push(...a.unmet, ...b.unmet);

  // receipts are validated first, the closure requirement runs second, the record is issued last
  const o = f.order || {};
  if (!(o.phaseStartedAt && o.validatedAt && o.closureStartedAt && o.issuedAt && o.phaseStartedAt <= o.validatedAt && o.validatedAt <= o.closureStartedAt && o.closureStartedAt <= o.issuedAt)) {
    unmet.push({ kind: 'order', id: 'finalization', reason: 'finalization did not validate the other receipts before executing the closure criteria and issuing the record' });
  }

  // a requirement counted verified while one of its dependencies is not: the DAG and the receipts disagree
  const bad = new Set([...a.badRequirements, ...b.badRequirements]);
  for (const r of reqs) {
    if (bad.has(r.id)) continue;
    const down = (r.dependencies || []).filter((d) => bad.has(d) || !reqs.some((x) => x.id === d));
    if (down.length) unmet.push({ kind: 'dag', id: r.id, reason: `has a passing receipt although its dependency ${down.join(', ')} does not` });
  }

  unmet.push(...checkEvidenceHashes(f.receipts));
  unmet.push(...checkRequiredGates({ gates: f.gates, requiredGates: config.requiredGates }));
  for (const id of f.expectedGates || []) {
    const g = f.gates.find((x) => x.id === id);
    if (!g) unmet.push({ kind: 'gate-missing', id, reason: 'release gate did not run' });
    else if (!g.ok) unmet.push({ kind: 'gate-failed', id, reason: `release gate failed (exit ${g.exitCode ?? 'n/a'})` });
  }
  const m = checkMeasured(f.measured);
  unmet.push(...m.unmet);
  unmet.push(...checkLimits({ profileLimits: f.limits?.profile, frozenLimits: f.limits?.frozen, config: config.limits, used: f.limits?.used, runBlockers: f.limits?.runBlockers }));
  unmet.push(...checkScope(f.scope || {}));

  const { before, afterEach = [], after } = f.treeDigests || {};
  const stable = !!before && before === after && afterEach.every((d) => d === before);
  if (!stable) unmet.push({ kind: 'tree-unstable', id: 'tree', reason: 'the source digest changed during the final phase (a watched file changed); closure requires one stable digest' });
  if (config.requireCleanTree !== false) {
    if (!f.git || f.git.dirty !== false) unmet.push({ kind: 'dirty-tree', id: 'tree', reason: f.git ? `the working tree is dirty (${f.git.dirtyCount} path(s)); closure binds the committed revision, so commit first` : 'the working tree state could not be read' });
  }

  const verifiedRequirements = reqs.filter((r) => !bad.has(r.id)).length;
  const passedCriteria = a.passedCriteria + b.passedCriteria;
  const counts = { requirements: { verified: verifiedRequirements, expected: config.expect.requirements }, criteria: { verified: passedCriteria, expected: config.expect.criteria } };
  if (verifiedRequirements !== config.expect.requirements) unmet.push({ kind: 'count', id: 'requirements', reason: `${verifiedRequirements} of ${config.expect.requirements} requirements verified` });
  if (passedCriteria !== config.expect.criteria) unmet.push({ kind: 'count', id: 'criteria', reason: `${passedCriteria} of ${config.expect.criteria} criteria verified` });

  const d = checkDeliverables(f.deliverables);
  unmet.push(...d.unmet);
  const open = dedupe([...m.open, ...d.open]);
  const un = dedupe(unmet);
  const closed = un.length === 0 && open.length === 0;
  return { verdict: closed ? 'all-required-criteria-verified' : 'incomplete', closed, stable, counts, unmet: un, open };
}

// ------------------------------------------------------------------ fact gathering (impure, no decisions)

const fileSha = (file) => { try { return sha256(readFileSync(file)); } catch { return null; } };

/** One receipt fact per requirement from the NEWEST evidence file on disk (never a silently older valid one). */
export function gatherReceipts({ L, manifest, tree, key }) {
  const out = new Map();
  for (const r of manifest.requirements) {
    const list = listEvidence(L, r.id);
    const newest = list[list.length - 1];
    if (!newest) { out.set(r.id, { id: r.id, found: false }); continue; }
    const ev = newest.ev;
    const a = assessOne(ev, { key, manifest, req: r, tree, checkLogs: true });
    out.set(r.id, {
      id: r.id, found: true, file: newest.file, fileSha256: fileSha(newest.file), evidenceId: ev.evidenceId,
      valid: a.valid, invalidReasons: a.invalidReasons, fresh: a.fresh, staleReasons: a.staleReasons,
      invoker: ev.invoker, phase: ev.phase, result: ev.result, createdAt: ev.createdAt, counts: ev.counts,
      criteria: (ev.criteria || []).map((c) => ({ id: c.id, state: c.state, reason: c.reason })), blockerType: ev.blocker?.type || null,
      logProblems: a.invalidReasons.filter((x) => /^log /.test(x)),
    });
  }
  return out;
}

/** Re-hash every cited evidence file right before issuance (the second half of the atomic-issue guard). */
export function rehashReceipts(receipts) {
  for (const rc of receipts.values()) if (rc.found) rc.fileSha256AtIssue = fileSha(rc.file);
  return receipts;
}

/**
 * HEAD and whether the working tree is dirty. `ignore` lists repository-relative paths that do not count: the requirements document
 * lives untracked in the repository root by convention, and it is already bound by its own hash in the frozen manifest, so its being
 * untracked must not make every closure impossible. Everything else untracked or modified counts.
 */
export function gitFacts(repoRoot, { ignore = [] } = {}) {
  const g = (...a) => { try { return execBoundedSync('git', a, { cwd: repoRoot, wallSeconds: 30, maxBuffer: 64 * 1024 * 1024 }).trim(); } catch { return null; } };
  const head = g('rev-parse', 'HEAD');
  const status = g('status', '--porcelain', '--', '.', ...ignore.map((p) => `:(exclude,literal)${p}`));
  if (head === null || status === null) return null;
  const lines = status.split('\n').filter(Boolean);
  return { head, dirty: lines.length > 0, dirtyCount: lines.length };
}

/**
 * Parse a measured gate's JSON output. kind "status-json": { status, synthetic }. kind "evaluation-gates": the evaluation driver's
 * per-layer results; the worst per-layer gate status wins and `synthetic: true` is carried. Unparseable output is unmeasured.
 */
export function parseMeasured(kind, text) {
  let j = null;
  try { j = JSON.parse(text); } catch { const i = text.indexOf('{'); if (i >= 0) { try { j = JSON.parse(text.slice(i, text.lastIndexOf('}') + 1)); } catch { /* fall through */ } } }
  if (!j || typeof j !== 'object') return { status: 'unmeasured', synthetic: false, reason: 'the gate printed no parseable JSON status' };
  if (kind === 'status-json') return { status: typeof j.status === 'string' ? j.status : 'unmeasured', synthetic: j.synthetic === true };
  const rank = ['pass', 'insufficient-population', 'unmeasured', 'fail'];
  const all = (j.results || []).map((r) => r.gatesOverall).filter(Boolean);
  if (!all.length) return { status: 'unmeasured', synthetic: j.synthetic === true, reason: 'no per-layer gate status was printed' };
  return { status: all.reduce((w, s) => (rank.indexOf(s) > rank.indexOf(w) ? s : w), 'pass'), synthetic: j.synthetic === true };
}

// ------------------------------------------------------------------ deliverables

const inside = (root, p) => { const abs = resolve(root, p); const rel = relative(root, abs); return rel && !rel.startsWith('..') && !isAbsolute(rel) ? abs : null; };

/** Existing repository files as a deliverable list entry. A missing or unreadable file is `missing`, never skipped. */
export function fileSetDeliverable(kind, repoRoot, paths) {
  const files = paths.map((p) => {
    const abs = inside(repoRoot, p);
    let ok = false; let size = 0;
    try { const st = abs ? statSync(abs) : null; ok = !!st?.isFile() && st.size > 0; size = st?.size || 0; } catch { /* missing */ }
    return { path: p, present: ok, sha256: ok ? fileSha(abs) : null, bytes: size };
  });
  const missing = files.filter((x) => !x.present).map((x) => x.path);
  return { kind, status: missing.length ? 'missing' : 'complete', files, reason: missing.length ? `missing or empty: ${missing.join(', ')}` : undefined };
}

/** The committed implementation diff since the revision the run was initialised at. Empty or unreadable is `missing`. */
export function implementationDiff({ repoRoot, baseHead, outFile }) {
  if (!baseHead) return { kind: 'implementation-diff', status: 'missing', reason: 'the run recorded no base revision, so there is nothing to diff against' };
  let buf;
  try { buf = execBoundedSync('git', ['diff', '--binary', '--no-color', baseHead, 'HEAD'], { cwd: repoRoot, maxBuffer: MAX_DIFF_BYTES + 1, wallSeconds: 120, encoding: 'buffer' }); } catch (e) {
    return { kind: 'implementation-diff', status: 'missing', reason: `git diff failed or exceeded ${MAX_DIFF_BYTES} bytes: ${e.code || e.message}` };
  }
  if (!buf.length) return { kind: 'implementation-diff', status: 'missing', reason: `no committed change since ${baseHead.slice(0, 12)}; an empty diff is not an implementation` };
  mkdirSync(join(outFile, '..'), { recursive: true });
  atomicWriteFile(outFile, buf);
  return { kind: 'implementation-diff', status: 'complete', path: outFile, sha256: sha256(buf), bytes: buf.length, base: baseHead };
}

/** The updated PRD ledger: one row per requirement from the receipts, plus whether each is closed. */
export function prdLedger({ manifest, receipts, unmetByRequirement, outFile }) {
  const rows = manifest.requirements.map((r) => {
    const rc = receipts.get(r.id) || {};
    const why = unmetByRequirement.get(r.id) || [];
    return { id: r.id, weight: r.weight, state: why.length ? 'open' : 'verified', evidenceId: rc.evidenceId || null, evidenceSha256: rc.fileSha256 || null, criteria: r.criteria.map((c) => ({ id: c.id, state: (rc.criteria || []).find((x) => x.id === c.id)?.state === 'pass' && !why.length ? 'pass' : 'open' })), unmet: why };
  });
  const ledger = { schemaVersion: CLOSURE_SCHEMA, prd: manifest.prd.path, prdSha256: manifest.prd.sha256, acceptanceHash: manifest.acceptanceHash, requirements: rows };
  atomicWriteJson(outFile, ledger);
  const open = rows.filter((x) => x.state === 'open').map((x) => x.id);
  return { kind: 'prd-ledger', status: open.length ? 'open' : 'complete', path: outFile, sha256: fileSha(outFile), reason: open.length ? `${open.length} requirement(s) still open: ${open.slice(0, 12).join(', ')}${open.length > 12 ? ', ...' : ''}` : undefined };
}

/** Which requirement each unmet item belongs to (criterion ids map to their requirement). */
export function unmetByRequirement(unmet, manifest) {
  const m = new Map();
  const reqOf = (id) => { if (manifest.requirements.some((r) => r.id === id)) return id; const x = id.match(/^(.+)\.AC\d+$/); return x && manifest.requirements.some((r) => r.id === x[1]) ? x[1] : null; };
  for (const u of unmet) { const r = reqOf(u.id); if (r) { if (!m.has(r)) m.set(r, []); m.get(r).push(`${u.kind}: ${u.reason}`); } }
  return m;
}

