// Source-to-artifact verification of a repair (verified-remediation PRD FR-16, M4-06): does the built artifact contain the verified
// repair, and does it still meet the contract?
//
// The image is read through the hardened archive reader (`src/artifact/`: `docker save` or OCI-layout tar, whiteout-aware layer merge;
// nothing is written to disk from the image). Three checks, all required for `artifact-verified`:
//
//   1. content   every file of the verified patch is in the image under the declared application directory with its PATCHED digest. A
//                file with its PRE-PATCH digest means the image was built from unpatched source (AC-16.1); a missing or different file
//                is a mismatch too.
//   2. packages  for a dependency repair, every package the verified lockfile resolves is in the image at that version, and no copy of
//                the advisory's package in the vulnerable range is anywhere under the application directory (AC-16.2).
//   3. behaviour the contract's oracle obligations are run again against the image's own files (the application and its node_modules as
//                the image ships them), through the trust boundary like any run. Each must meet its patched expectation.
//
// A signature, a label or a deployment receipt never sets any of this (AC-16.6): only these executed comparisons do. Staging and
// deployment are not observed here: the record's `environment` stays `not-checked`.
import { buildImageInventory } from '../artifact/inventory.js';
import { digestOf } from '../posture/assurance/identity.js';
import { satisfies } from './dependencies.js';
import { runObligation, judge } from './lab.js';
import { withoutQuarantined } from './counterexamples.js';

const norm = (d) => String(d || '').replace(/^\/+|\/+$/g, '');

/** Read an image archive into its merged file view. Throws on an archive the reader refuses. */
export function readImage(buf) {
  const { inventory, mergedFilesystem } = buildImageInventory(buf, { manifestParser: () => [] });
  return { digest: inventory.digest, files: mergedFilesystem.fileContents, truncated: !!inventory.materializationTruncated, unsafe: inventory.unsafeEntries.length };
}

/** The content and package checks. Pure over the image's file view. */
export function compareArtifact({ record, plan, image, appDir }) {
  const base = norm(appDir);
  const at = (rel) => image.files[base ? `${base}/${rel}` : rel];
  const files = [];
  const patch = record.exactPatch || { files: {}, beforeDigests: {}, afterDigests: {} };
  for (const rel of Object.keys(patch.afterDigests || {})) {
    const text = at(rel);
    const after = patch.afterDigests[rel]; const before = patch.beforeDigests?.[rel] ?? null;
    if (after === null) { files.push({ file: rel, state: text === undefined ? 'removed' : 'still-present' }); continue; }
    if (text === undefined) { files.push({ file: rel, state: 'absent' }); continue; }
    const d = digestOf(text);
    files.push({ file: rel, state: d === after ? 'patched' : d === before ? 'unpatched' : 'different' });
  }
  const problems = files.filter((f) => !['patched', 'removed'].includes(f.state)).map((f) => (f.state === 'unpatched' ? `${f.file} is the pre-patch version: the image was built from unpatched source` : `${f.file}: ${f.state}`));
  const packages = [];
  const dep = plan.contract.obligations.find((o) => o.kind === 'dependency-resolved')?.inputs;
  if (dep) {
    let lock = null;
    try { lock = JSON.parse(patch.files?.['package-lock.json'] ?? ''); } catch { /* the lockfile was not part of the patch */ }
    for (const [p, e] of Object.entries(lock?.packages || {})) {
      if (!p) continue;
      let meta = null;
      try { meta = JSON.parse(at(`${p}/package.json`) ?? 'null'); } catch { /* unreadable */ }
      const state = !meta ? 'absent' : meta.version === e.version ? 'present' : `version ${meta.version}`;
      packages.push({ path: p, version: e.version, state });
      if (state !== 'present') problems.push(`${p}@${e.version} is ${state === 'absent' ? 'absent from' : `${state} in`} the image`);
    }
    const prefix = base ? `${base}/` : '';
    for (const [file, text] of Object.entries(image.files)) {
      if (!file.startsWith(prefix) || !file.endsWith(`node_modules/${dep.package}/package.json`)) continue;
      let v = null; try { v = JSON.parse(text).version; } catch { /* unreadable */ }
      if (v && satisfies(v, dep.vulnerable)) problems.push(`the image ships ${dep.package}@${v} at ${file.slice(prefix.length, -'/package.json'.length)}, in the vulnerable range ${dep.vulnerable}`);
    }
  }
  return { files, packages, problems };
}

/**
 * Run the contract's oracle obligations against the image's files. `config` must enable execution. Returns one result per obligation.
 */
export async function rerunOnArtifact({ record, plan, image, appDir, config, deps = {} }) {
  const base = norm(appDir);
  const prefix = base ? `${base}/` : '';
  const app = {};
  for (const rel of plan.contract.profile.application.files) { const t = image.files[`${prefix}${rel}`]; if (t !== undefined) app[rel] = t; }
  for (const [file, text] of Object.entries(image.files)) if (file.startsWith(`${prefix}node_modules/`)) app[file.slice(prefix.length)] = text;
  const q = record.quarantined || [];
  const out = [];
  for (const ob of plan.contract.obligations.filter((o) => o.oracleId)) {
    const inputs = withoutQuarantined(ob.inputs, q.filter((x) => x.obligation === ob.id));
    const res = await runObligation(ob, app, { config, entry: plan.entry, hypothesisId: `${plan.contract.contractId}:${ob.id}:artifact`, inputs, ...deps });
    out.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, status: judge(res.observed, ob.patchedExpectation), reason: String(res.reason || '').slice(0, 300), receiptDigest: res.receipt ? digestOf(res.receipt.recordId || res.receipt) : null });
  }
  return out;
}

/** The artifact state and the record's `source` block from the three checks. */
export function artifactVerdict({ image, appDir, comparison, checks }) {
  const failedChecks = (checks || []).filter((c) => c.status !== 'passed');
  const executed = Array.isArray(checks) && checks.length > 0 && checks.every((c) => !['unavailable', 'invalid'].includes(c.status));
  let artifact;
  if (comparison.problems.length || failedChecks.some((c) => c.status === 'failed')) artifact = 'artifact-mismatch';
  else if (!executed || failedChecks.length) artifact = 'unavailable';
  else artifact = 'artifact-verified';
  return {
    artifact,
    source: { artifactDigest: image.digest, appDir: norm(appDir), files: comparison.files, packages: comparison.packages, checks: checks || [], problems: [...comparison.problems, ...failedChecks.map((c) => `${c.obligation} on the artifact: ${c.status} (${c.reason})`)].slice(0, 40), note: 'content and behaviour of this image only; nothing about staging or deployment' },
  };
}
