// The release assurance bundle for a closure run (REL-003.AC03). It reuses the product's own portable-evidence modules
// (posture/portfolio/manifest.js and bundle.js) rather than inventing a second format: a manifest that lists every requirement and gate as
// completed, incomplete or unsupported, the signed receipts the claim rests on, and a replay manifest. Whatever is not completed is
// listed under incomplete or unsupported with its gap, so the bundle's own `complete` flag is false until every check is completed.
//
// What this bundle is not: it is not signed (signing starts only after evidence validation is complete and uses the protected signer),
// and it carries no vulnerability scan, so its findings count is zero BY DECLARATION and a residual risk says so.
import { readFileSync, rmSync, existsSync } from 'node:fs';
import { basename } from 'node:path';
import { buildManifest, validateManifest } from '../../../scanner/src/posture/portfolio/manifest.js';
import { exportBundle, verifyBundle } from '../../../scanner/src/posture/portfolio/bundle.js';
import { digestOf, digestOfBytes } from '../../../scanner/src/posture/assurance/identity.js';

const safeId = (s) => String(s).replace(/[^A-Za-z0-9._-]/g, '_');

/**
 * Build, export and re-verify the bundle in `outDir` (must not exist). Returns a deliverable entry:
 * status `complete` only when the manifest is complete AND the exported bundle verifies; `open` when it verifies but checks remain;
 * `missing` when it could not be produced or does not verify.
 */
export function buildAssuranceBundle({ repoRoot, config, manifest, receipts, unmetByReq, gates, measured, git, artifactPaths, outDir, toolchain = {} }) {
  const kind = 'release-assurance-bundle';
  try {
    if (!git?.head || !/^[0-9a-f]{40,64}$/.test(git.head)) return { kind, status: 'missing', reason: 'no committed revision is known, so the bundle has no subject commit' };
    const artifacts = [];
    for (const p of artifactPaths) {
      const abs = `${repoRoot}/${p}`;
      if (!existsSync(abs)) return { kind, status: 'missing', reason: `build artifact ${p} is missing, and a release manifest must bind at least one artifact digest` };
      artifacts.push({ name: p, digest: digestOfBytes(readFileSync(abs)) });
    }
    const repository = basename(repoRoot);
    const policy = { id: 'loop-final-closure', digest: digestOf(config), blockingSeverity: 'high' };
    const recs = []; const receiptContents = [];
    const refsOf = new Map();
    for (const r of manifest.requirements) {
      const rc = receipts.get(r.id);
      if (!rc?.found) continue;
      let content;
      try { content = JSON.parse(readFileSync(rc.file, 'utf8')); } catch { continue; }
      const id = safeId(rc.evidenceId);
      recs.push({ id, digest: digestOf(content), repository, commit: git.head });
      receiptContents.push({ id, content });
      refsOf.set(r.id, id);
    }
    const checks = { completed: [], incomplete: [], unsupported: [], waived: [] };
    const mandatory = [];
    for (const r of manifest.requirements) {
      mandatory.push(r.id);
      const why = unmetByReq.get(r.id) || [];
      const ref = refsOf.get(r.id);
      if (!why.length && ref) checks.completed.push({ id: r.id, statement: `${r.id} has a fresh, controller-issued receipt with every criterion passing`, evidenceRefs: [ref] });
      else checks.incomplete.push({ id: r.id, statement: `${r.id} is not verified`, evidenceRefs: ref ? [ref] : [], gaps: why.length ? why.slice(0, 8) : ['no receipt'] });
    }
    // A gate has no signed envelope; its result record is bound as a receipt of its own so a completed gate cites real evidence.
    const gateReceipt = (rid, content) => { recs.push({ id: rid, digest: digestOf(content), repository, commit: git.head }); receiptContents.push({ id: rid, content }); return rid; };
    for (const g of gates) {
      mandatory.push(`gate:${g.id}`);
      const rid = gateReceipt(`gate-${safeId(g.id)}`, { kind: 'gate-result', id: g.id, argv: g.argv, cwd: g.cwd, exitCode: g.exitCode, outcome: g.outcome, ok: g.ok, durationMs: g.durationMs });
      if (g.ok) checks.completed.push({ id: `gate:${g.id}`, statement: `release gate ${g.id} exited as expected`, evidenceRefs: [rid] });
      else checks.incomplete.push({ id: `gate:${g.id}`, statement: `release gate ${g.id} did not pass`, evidenceRefs: [], gaps: [g.reason || `exit ${g.exitCode}`] });
    }
    for (const m of measured) {
      mandatory.push(`measured:${m.id}`);
      const rid = gateReceipt(`measured-${safeId(m.id)}`, { kind: 'measured-gate-result', id: m.id, group: m.group, status: m.status ?? null, synthetic: m.synthetic === true, ran: m.ran !== false, reason: m.reason ?? null });
      if (m.status === 'pass' && m.synthetic !== true && m.ran !== false) checks.completed.push({ id: `measured:${m.id}`, statement: `measured ${m.group} gate ${m.id} passed on a non-synthetic population`, evidenceRefs: [rid] });
      else checks.unsupported.push({ id: `measured:${m.id}`, statement: `measured ${m.group} gate ${m.id} is not measured here`, evidenceRefs: [], gaps: [m.synthetic === true ? `status ${m.status} on a synthetic population; no adjudicated population exists` : (m.reason || `status ${m.status || 'unmeasured'}`)] });
    }
    const open = [...checks.incomplete, ...checks.unsupported];
    const m = buildManifest({
      subject: { repository, commit: git.head, bundleDigest: digestOf(artifacts), policyDigest: policy.digest },
      dependencies: [], artifacts, scope: { description: 'Requirement receipts, release gates and measured gates of one final closure run', mandatory },
      graphSnapshot: { digest: digestOf({ kind: 'requirement-dag', requirements: manifest.requirements.map((r) => [r.id, [...(r.dependencies || [])].sort()]) }) },
      invariantVersions: [], verificationReceipts: recs, checks, policy, findings: { total: 0, blocking: 0 },
      residualRisks: [
        { id: 'no-vulnerability-scan', statement: 'This bundle describes release closure of the implementation loop. It binds no vulnerability scan, so its zero findings count is a declaration, not a result.', severity: 'info' },
        ...open.slice(0, 40).map((c) => ({ id: safeId(c.id), statement: `${c.id}: ${c.gaps[0]}`, severity: 'medium' })),
      ],
    });
    const v = validateManifest(m);
    if (!v.ok) return { kind, status: 'missing', reason: `the assurance manifest is invalid (${v.errors[0].code} ${v.errors[0].path})` };
    rmSync(outDir, { recursive: true, force: true });
    const ex = exportBundle({
      outDir, manifest: m, findings: [], provenance: { source: 'release closure final phase', head: git.head },
      replayManifests: [{ id: 'release-closure-replay', prerequisites: [{ code: 'controller-final-phase', statement: 'replay by running the controller final phase against the same commit with the same profile' }] }],
      toolchain, receipts: receiptContents,
    });
    const vb = verifyBundle(outDir);
    if (!vb.ok) return { kind, status: 'missing', reason: `the exported bundle does not verify: ${vb.errors[0]?.code}` };
    return {
      kind, status: m.complete ? 'complete' : 'open', path: outDir, bundleDigest: ex.bundleDigest, manifestId: m.id, complete: m.complete,
      reason: m.complete ? undefined : `${open.length} mandatory check(s) are not completed (${checks.incomplete.length} incomplete, ${checks.unsupported.length} unsupported); the bundle says so and is not a completion claim`,
    };
  } catch (e) {
    return { kind, status: 'missing', reason: `could not assemble the bundle: ${String(e.message || e).slice(0, 300)}` };
  }
}
