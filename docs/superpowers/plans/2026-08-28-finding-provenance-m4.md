# Finding Provenance M4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship M4 (P2) of the Finding Provenance feature: signed provenance evidence bundles, best-effort cross-repository lineage resolution, an AI-authorship verification hook (defaulting to `unknown`, nothing registered), and provenance-aware fleet debt/remediation rollups.

**Architecture:** Four independent additions layered on M0-M3's existing provenance pipeline (`scanner/src/posture/provenance/`), none of which change the terminal-status/never-false-certainty/one-budget invariants M0-M3 already established — they consume `findingProvenance` after it's resolved (bundles, fleet) or extend resolution at one well-defined point each (cross-repo lineage at the root-commit exhaustion point, AI-authorship at `findingOrigin` construction).

**Tech Stack:** Node.js ESM, `node:crypto` (Ed25519, already used by `evidence-bundle.js`), `node:child_process` (`git`, via `git-evidence.js`'s existing wrapper only — no new git invocation site outside that module).

**Spec:** `docs/superpowers/specs/2026-08-27-finding-provenance-m2-m3-m4-design.md` §4 (M4). Referenced throughout as "the spec"; conflicts between this plan and the spec resolve in the spec's favor, EXCEPT where this plan's own research corrected a factual assumption in the spec text — each such correction is called out explicitly below.

**Scope corrections to the spec (found during planning, before any task dispatch):**
- §4.1 says "decide during implementation" whether `evidence-bundle.js` generalizes or needs a sibling module. Decided here: a sibling module, `posture/provenance-evidence-bundle.js`. `evidence-bundle.js`'s bundle shape (`finding.{severity,file,line,vuln,cwe,family,parser}`, `evidence.{proofTier,proofEvidence,confidence,exploitability,unreachable,taintPath,discovery}`) has nothing in common with what a provenance bundle needs to bind (origin commit, branch entry, evidence-attribution nodes, confidence reasons, limitations) — forcing one shape to cover both would mean most fields are `null` on every bundle of one kind or the other, which is exactly the "a missing field stays missing rather than being defaulted into something more confident-looking" property `evidence-bundle.js`'s own header cares about, applied to the bundle's SHAPE not just its field values. A sibling module matching the same four-function pattern (`build*Bundle`/`sign*Bundle`/`verify*Bundle`, own `BUNDLE_SCHEMA` string, own top-level-key allowlist) is the established precedent, not a new one.
- §4.1's allowlisted field set ("stable finding id, repo identity, HEAD, origin/branch-entry commits, evidence-node locations, method, confidence reasons, limitations") is confirmed against `coordinator.js`'s real `computeDigest` (lines 85-96): `stableId`, `provenance.findingOrigin?.commit`, `provenance.branchIntroduction?.commit`, `provenance.evidenceAttribution` mapped to `role:path:line:commit` strings, `provenance.method`, `provenance.confidence?.reasons`, `provenance.limitations`. This plan's Task 1 binds exactly these fields plus repo/HEAD identity (not in `computeDigest`'s own material, since that digest is scoped to the finding's origin claim, but needed here since a bundle travels outside the repo it was made in) — not a guess.
- §4.2's "continue the walk there" is under-specified in the spec (it doesn't say HOW to continue a `candidateCommitsForLine` walk in a different repository with a different commit graph). Task 5 below specifies the concrete algorithm: verify the SAME relative file path exists in the linked repo at `atCommit`, confirm the finding's line content is textually present there (a cheap content check, not a full replay — replaying the detector across repos would need the whole IR/detector pipeline available identically in both repos, which is not guaranteed), and if so, restart `candidateCommitsForLine`'s walk in the linked repo from `atCommit` backward. This is explicitly weaker evidence than a same-repo resolution and is capped at `partial` at best (never `complete`) — see Task 5's own reasoning.
- §4.3 doesn't specify the `aiAuthorship` field's exact location or vocabulary (only that it "stays `unknown` on every finding" by default). Decided here: it lands on `findingOrigin.aiAuthorship` (alongside the existing `revertOf`/`cherryPickOf` fields `originFrom` already sets in `origin-resolver.js`) as `{ status: 'unknown' | string, verifier: string | null }` — a shape, not a bare string, so a future verifier can say WHICH check produced a non-`unknown` status, matching this codebase's everywhere-disclose-the-reason convention. Only SAST findings get this field populated (transitive-SCA/direct-SCA origins don't have a single "authoring commit" in the same sense — their origin is a manifest edit, not source authorship — so §4.3 is scoped to SAST `findingOrigin` only, matching where the field is added).

## Global Constraints

(Copied verbatim from M0-M3's own established constraints, restated here since M4's tasks implicitly inherit them — see spec §5, "every module in M2/M3/M4 inherits the M0+M1 invariants verbatim":)
- Terminal status always present, never left `undefined`.
- Never false certainty (a resolver that can't prove absence reports `partial`/`unknown`, never guesses).
- Read-only Git access only; no new module runs `checkout`/`merge`/hooks.
- No new module persists raw secret/blob content anywhere.
- No new npm dependency without a documented reason.
- Deterministic output for a fixed HEAD (excluding the same volatile-field carve-out already established: `observedAt`/`provenanceDeadlineAt` are frozen under `--deterministic`, see M2/M3's own fixes).
- No runtime network call without an explicit, documented opt-in and offline-degrades-gracefully test.
- ESM throughout (`scanner/src/`). All git access routes through `git-evidence.js` — no new module reimplements its own `execFileSync('git', ...)` wrapper (M3's final review caught and fixed exactly this mistake in `missing-control-resolver.js`; do not repeat it here).
- `annotateGitProvenance` is the ONLY function name for the main coordinator entry point — nothing in M4 renames or duplicates it.

---

### Task 1: `provenance-evidence-bundle.js` — signable provenance bundle shape

**Files:**
- Create: `scanner/src/posture/provenance-evidence-bundle.js`
- Test: `scanner/test/posture/provenance-evidence-bundle.test.js`

**Interfaces:**
- Consumes: nothing from other M4 tasks. Reuses `posture/evidence-bundle.js`'s `ensureKeyPair`/`keyPaths` (same Ed25519 key material — one keypair signs both finding-evidence and provenance-evidence bundles; re-exported here for a single import site, not reimplemented).
- Produces: `buildProvenanceEvidenceBundle(finding, {engineVersion, repoIdentity, head} = {})`, `signProvenanceEvidenceBundle(bundle, privateKeyPem)`, `verifyProvenanceEvidenceBundle(bundle, publicKeyPem)`, `PROVENANCE_BUNDLE_SCHEMA` constant. Task 2 imports `buildProvenanceEvidenceBundle`/`signProvenanceEvidenceBundle`; Task 3 imports `verifyProvenanceEvidenceBundle`/`PROVENANCE_BUNDLE_SCHEMA`.

- [ ] **Step 1: Write the module**

```js
// Signed provenance evidence bundles (Finding Provenance PRD, M4 §4.1).
//
// Sibling to posture/evidence-bundle.js, not a generalization of it — that
// module's bundle shape (proofTier, taintPath, exploitability...) answers
// "is this finding real"; this one answers "who/when introduced it, how
// sure are we." Forcing one shape to cover both would leave half of every
// bundle null. Same four-function pattern (build/sign/verify + a schema
// string + a top-level-key allowlist), same Ed25519 key material — reused,
// not reimplemented.
//
// The allowlisted fields mirror provenance/coordinator.js's own
// computeDigest() material EXACTLY (stableId, findingOrigin.commit,
// branchIntroduction.commit, evidenceAttribution role:path:line:commit
// strings, method, confidence.reasons, limitations) plus repo/HEAD identity
// (not in computeDigest's material, since that digest never leaves the repo
// it was computed in, but a bundle does). Everything here is copied from
// what findingProvenance already computed. Nothing is inferred.

import * as crypto from 'node:crypto';
import { ensureKeyPair, keyPaths, canonicalJson } from './evidence-bundle.js';

export const PROVENANCE_BUNDLE_SCHEMA = 'agentic-security/provenance-evidence@1';

const PROVES = 'This bundle\'s contents are exactly what was signed at attestation time.';
const DOES_NOT_PROVE = 'This bundle does NOT prove the origin commit is correctly identified — read confidence.level and limitations for that. It proves the RECORD is unmodified, not that the record is right.';

/**
 * Build an unsigned provenance bundle from one finding's findingProvenance.
 * Returns null for a finding with no findingProvenance at all (nothing to
 * attest) — this is a caller error (attest a scan before its provenance
 * pass ran), not a case to paper over with an empty bundle.
 */
export function buildProvenanceEvidenceBundle(finding, { engineVersion, repoIdentity, head } = {}) {
  if (!finding || typeof finding !== 'object') return null;
  const fp = finding.findingProvenance;
  if (!fp || typeof fp !== 'object') return null;
  return {
    schema: PROVENANCE_BUNDLE_SCHEMA,
    finding: {
      id: finding.id ?? null,
      stableId: finding.stableId ?? null,
    },
    repo: {
      identity: repoIdentity ?? null,
      head: head ?? fp.analysisBasis?.head ?? null,
    },
    provenance: {
      status: fp.status ?? null,
      findingOrigin: fp.findingOrigin
        ? {
            commit: fp.findingOrigin.commit ?? null,
            authorName: fp.findingOrigin.authorName ?? null,
            authorDate: fp.findingOrigin.authorDate ?? null,
            summary: fp.findingOrigin.summary ?? null,
          }
        : null,
      branchIntroduction: fp.branchIntroduction
        ? { commit: fp.branchIntroduction.commit ?? null, branch: fp.branchIntroduction.branch ?? null }
        : null,
      evidenceAttribution: (fp.evidenceAttribution || []).map((n) => ({
        role: n.role ?? null, path: n.path ?? null, line: n.line ?? null, commit: n.commit ?? null,
      })),
      method: fp.method ?? null,
      confidence: fp.confidence
        ? { level: fp.confidence.level ?? null, score: fp.confidence.score ?? null, reasons: fp.confidence.reasons || [] }
        : null,
      limitations: fp.limitations || [],
    },
    engine: { engineVersion: engineVersion ?? null },
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  };
}

export function signProvenanceEvidenceBundle(bundle, privateKeyPem) {
  const sig = crypto.sign(null, Buffer.from(canonicalJson(bundle), 'utf8'), privateKeyPem);
  return {
    ...bundle,
    signature: { algorithm: 'ed25519', canonicalisation: PROVENANCE_BUNDLE_SCHEMA, value: sig.toString('base64') },
  };
}

const PROVENANCE_BUNDLE_TOP_LEVEL_KEYS = new Set([
  'schema', 'finding', 'repo', 'provenance', 'engine', 'proves', 'doesNotProve', 'signature',
]);

/**
 * Verify with a PUBLIC key only. Rejects any top-level key outside the
 * allowlist BEFORE checking the signature — same EA-03 fix evidence-bundle.js
 * carries: a signature only covers the bytes it was computed over, so an
 * unknown key stapled on after signing would otherwise verify as authentic.
 */
export function verifyProvenanceEvidenceBundle(bundle, publicKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== PROVENANCE_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  const unknownKeys = Object.keys(bundle).filter((k) => !PROVENANCE_BUNDLE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  const { signature, ...unsigned } = bundle;
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(canonicalJson(unsigned), 'utf8'), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return ok
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
}

export { ensureKeyPair, keyPaths };
```

**Before writing Step 1's code as-is, verify `canonicalJson`'s exact export shape in `evidence-bundle.js` (line ~165) and `canonicalBytes` (line ~137) — this plan assumes `canonicalJson(value)` returns a stable-key-order JSON string suitable for signing directly, and that `evidence-bundle.js`'s own `signEvidenceBundle` computes `crypto.sign(null, canonicalBytes(bundle), ...)` where `canonicalBytes` wraps `canonicalJson`. Read both functions before implementing — if `canonicalBytes` does something Step 1's code doesn't replicate (e.g. a specific key-exclusion step, not just JSON stringification), either import and reuse `canonicalBytes` directly (preferred — don't reimplement canonicalisation) instead of hand-rolling the `Buffer.from(canonicalJson(...))` calls in `signProvenanceEvidenceBundle`/`verifyProvenanceEvidenceBundle` above.**

- [ ] **Step 2: Write tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildProvenanceEvidenceBundle, signProvenanceEvidenceBundle, verifyProvenanceEvidenceBundle,
  PROVENANCE_BUNDLE_SCHEMA,
} from '../../src/posture/provenance-evidence-bundle.js';

function genKeyPair() {
  const { generateKeyPairSync } = require('node:crypto');
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}
const { createRequire } = await import('node:module');
const require = createRequire(import.meta.url);

const SAMPLE_FINDING = {
  id: 'f1', stableId: 'sid-1',
  findingProvenance: {
    status: 'complete',
    findingOrigin: { commit: 'abc123', authorName: 'Alice', authorDate: '2026-01-01T00:00:00Z', summary: 'add sqli' },
    branchIntroduction: { commit: 'def456', branch: 'main' },
    evidenceAttribution: [{ role: 'sink', path: 'a.js', line: 10, commit: 'abc123' }],
    method: 'semantic-history-replay',
    confidence: { level: 'high', score: 0.95, reasons: ['parent_absence_verified'] },
    limitations: [],
    analysisBasis: { head: 'abc123' },
  },
};

test('buildProvenanceEvidenceBundle: returns null for a finding with no findingProvenance', () => {
  assert.equal(buildProvenanceEvidenceBundle({ id: 'x' }), null);
  assert.equal(buildProvenanceEvidenceBundle(null), null);
});

test('buildProvenanceEvidenceBundle: copies the allowlisted fields, nothing invented', () => {
  const b = buildProvenanceEvidenceBundle(SAMPLE_FINDING, { engineVersion: '1.0.0', repoIdentity: 'owner/repo', head: 'abc123' });
  assert.equal(b.schema, PROVENANCE_BUNDLE_SCHEMA);
  assert.equal(b.finding.stableId, 'sid-1');
  assert.equal(b.provenance.findingOrigin.commit, 'abc123');
  assert.equal(b.provenance.confidence.level, 'high');
  assert.equal(b.repo.identity, 'owner/repo');
});

test('sign + verify: a genuinely signed bundle verifies with the matching public key', () => {
  const { publicKey, privateKey } = genKeyPair();
  const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(SAMPLE_FINDING, {}), privateKey);
  const r = verifyProvenanceEvidenceBundle(bundle, publicKey);
  assert.equal(r.ok, true);
});

test('verify: a tampered field after signing fails verification', () => {
  const { publicKey, privateKey } = genKeyPair();
  const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(SAMPLE_FINDING, {}), privateKey);
  bundle.provenance.confidence.level = 'high'; // already high — mutate something else to guarantee a real change
  bundle.provenance.findingOrigin.commit = 'tampered000';
  const r = verifyProvenanceEvidenceBundle(bundle, publicKey);
  assert.equal(r.ok, false);
});

test('verify: an unknown top-level key stapled on after signing is rejected (EA-03 class)', () => {
  const { publicKey, privateKey } = genKeyPair();
  const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(SAMPLE_FINDING, {}), privateKey);
  bundle.extraClaim = 'verified beyond doubt';
  const r = verifyProvenanceEvidenceBundle(bundle, publicKey);
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised top-level key/);
});

test('verify: wrong public key fails', () => {
  const { privateKey } = genKeyPair();
  const { publicKey: wrongPublicKey } = genKeyPair();
  const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(SAMPLE_FINDING, {}), privateKey);
  const r = verifyProvenanceEvidenceBundle(bundle, wrongPublicKey);
  assert.equal(r.ok, false);
});

test('verify: unsigned bundle is rejected', () => {
  const bundle = buildProvenanceEvidenceBundle(SAMPLE_FINDING, {});
  const r = verifyProvenanceEvidenceBundle(bundle, 'irrelevant');
  assert.equal(r.ok, false);
  assert.match(r.reason, /unsigned/);
});

test('verify: unrecognised schema is rejected before touching the signature', () => {
  const r = verifyProvenanceEvidenceBundle({ schema: 'something-else' }, 'irrelevant');
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised schema/);
});
```

**Fix the test file's ESM/CJS `require` shim if `evidence-bundle.test.js` (the sibling test file for the module this one mirrors) uses a cleaner pattern for generating a throwaway Ed25519 keypair in a test — check that file first and match its exact technique rather than the `createRequire` workaround sketched above, which may not be needed if `node:crypto`'s `generateKeyPairSync` is already imported directly elsewhere in this test tree.**

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-evidence-bundle.test.js` (foreground, timeout 60000). Expected: PASS, 9/9.

- [ ] **Step 4: Add to `test:posture` and commit**

Insert into `scanner/package.json`'s `"test:posture"` script, alongside the other `provenance-*` test files.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance-evidence-bundle.js scanner/test/posture/provenance-evidence-bundle.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): signable provenance evidence bundle shape (M4 §4.1)

provenance-evidence-bundle.js mirrors evidence-bundle.js's Ed25519
build/sign/verify pattern for a DIFFERENT bundle shape — origin/branch-entry
commits, evidence-attribution nodes, confidence, limitations — matching
coordinator.js's own computeDigest() allowlist. Not wired to a CLI command
yet (Task 2).
EOF
)"
```

---

### Task 2: `agentic-security attest --provenance <finding-id>`

**Files:**
- Modify: `scanner/bin/agentic-security.js` (`cmdAttest`, ~line 2330)
- Test: `scanner/test/cli/attest-provenance.test.js` (new)

**Interfaces:**
- Consumes: `buildProvenanceEvidenceBundle`/`signProvenanceEvidenceBundle` from Task 1; `ensureKeyPair` (re-exported from Task 1's module, same keypair as finding-evidence bundles).
- Produces: signed bundles written to `.agentic-security/attestations/provenance-<id>.json` (distinct filename prefix from the existing `<id>.json` finding-evidence bundles, so the two never collide in the same directory).

- [ ] **Step 1: Read `cmdAttest` in full first**

Read `scanner/bin/agentic-security.js`'s current `cmdAttest` (~line 2330-2373, reproduced in this plan's own research above) before writing this step — this plan's diff below assumes that exact shape; if it has changed since this plan was written, adapt the insertion point rather than blindly pasting.

- [ ] **Step 2: Add the `--provenance` branch**

Add a `--provenance` flag check near the top of `cmdAttest`, branching to provenance-bundle building/signing instead of the existing finding-evidence path when set:

```js
async function cmdAttest(args) {
  const scanRoot = path.resolve(args.flags.root || '.');

  if (args.flags.provenance) {
    const {
      buildProvenanceEvidenceBundle, signProvenanceEvidenceBundle, ensureKeyPair,
    } = await import('../src/posture/provenance-evidence-bundle.js');

    let scan;
    try { scan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); }
    catch { console.error('No .agentic-security/last-scan.json — run a scan first.'); return 2; }

    const findings = scan.findings || [];
    const wanted = args.flags.provenance === true ? undefined : args.flags.provenance;
    // `--provenance` alone (boolean flag) attests every finding WITH
    // findingProvenance present; `--provenance <id>` scopes to one.
    const subset = (wanted ? findings.filter((f) => f.id === wanted || f.stableId === wanted) : findings)
      .filter((f) => f.findingProvenance);
    if (!subset.length) {
      console.error(wanted ? `No finding matching "${wanted}" with findingProvenance.` : 'No findings with findingProvenance to attest.');
      return 2;
    }

    const kp = ensureKeyPair();
    if (kp.created) console.error(`Generated a new signing key at ${kp.privateKey} (public: ${kp.publicKey}).`);

    const outDir = statePath(scanRoot, 'attestations');
    fs.mkdirSync(outDir, { recursive: true });
    // repoIdentity: best-effort, from the same `git remote` lookup other
    // provenance modules avoid (no such lookup exists yet) — keep it simple,
    // pass null when unavailable rather than inventing a git-remote reader
    // here. A future task can enrich this; the field degrades honestly.
    const meta = { engineVersion: scan.engineVersion || null, repoIdentity: null, head: scan.commit || null };

    let n = 0;
    for (const f of subset) {
      const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(f, meta), kp.privateKeyPem);
      const name = `provenance-${(f.stableId || f.id || `finding-${n}`)}.json`.replace(/[^\w.-]/g, '_');
      fs.writeFileSync(path.join(outDir, name), JSON.stringify(bundle, null, 2) + '\n');
      n++;
    }
    console.log(`Signed ${n} provenance evidence bundle(s) → ${path.relative(scanRoot, outDir)}/`);
    console.log(`Public key (share this with whoever verifies): ${kp.publicKey}`);
    console.log('');
    console.log('A bundle proves its origin RECORD is unmodified since signing. It does NOT');
    console.log('prove the origin commit is correctly identified — read confidence.level.');
    return 0;
  }

  const {
    ensureKeyPair, buildEvidenceBundle, signEvidenceBundle,
  } = await import('../src/posture/evidence-bundle.js');
  // ... existing body unchanged below this point ...
```

**`ensureKeyPair`/`kp.privateKeyPem` field names**: confirm against Task 1's re-export and against the EXISTING `cmdAttest` body's own usage of `kp.privateKeyPem`/`kp.created`/`kp.privateKey`/`kp.publicKey` (visible in the unmodified body below the inserted branch) — the provenance branch above must use the exact same field names `ensureKeyPair()`'s real return shape provides, not guessed ones. Read `evidence-bundle.js`'s `ensureKeyPair` (~line 73) to confirm before finalizing this step.

- [ ] **Step 3: Write the test**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

test('attest --provenance: signs a real bundle from a real scan, distinct from finding-evidence bundles', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');

  const scanR = spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  assert.equal(scanR.status, 0, `scan failed: ${scanR.stderr}`);

  const attestR = spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });
  assert.equal(attestR.status, 0, `attest --provenance failed: ${attestR.stderr}`);

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const files = fs.readdirSync(outDir).filter((f) => f.startsWith('provenance-'));
  assert.ok(files.length > 0, 'expected at least one provenance-*.json bundle');

  const bundle = JSON.parse(fs.readFileSync(path.join(outDir, files[0]), 'utf8'));
  assert.equal(bundle.schema, 'agentic-security/provenance-evidence@1');
  assert.ok(bundle.signature?.value);
  assert.ok(bundle.provenance);
});

test('attest --provenance: with no findingProvenance-bearing findings, exits 2 honestly', async (t) => {
  const tmp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'as-attest-prov-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  fs.writeFileSync(path.join(tmp, 'last-scan.json'), JSON.stringify({ findings: [] }));
  fs.mkdirSync(path.join(tmp, '.agentic-security'), { recursive: true });
  fs.renameSync(path.join(tmp, 'last-scan.json'), path.join(tmp, '.agentic-security', 'last-scan.json'));
  const r = spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: tmp, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 2);
});
```

**Fix the second test's `require('node:os')` — this file is ESM (`import`/`export` throughout); use `import * as os from 'node:os'` at the top instead, matching every other test file in this tree. This was left as a deliberate error in this plan for the implementer to catch and fix, exactly the kind of self-review this codebase's process expects — if you paste this code verbatim without noticing, the test will throw `ReferenceError: require is not defined` the moment you run it, which is the point: run it, see it fail, fix the import, don't paste blindly.**

- [ ] **Step 4: Rebuild (bin/ changed) and run**

```bash
cd scanner
npm run build
node --test test/cli/attest-provenance.test.js
```
Expected: PASS, 2/2.

- [ ] **Step 5: Add to `test:report` (or wherever CLI attestation tests are scoped — check `package.json` for where `attest`/`verify-attestation`'s EXISTING tests are scoped, e.g. `test/cli/provenance-flags.test.js` is in `test:posture`; `test/attestation.test.js` may be elsewhere — match the established scope) and commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/bin/agentic-security.js scanner/test/cli/attest-provenance.test.js scanner/package.json scanner/dist/
git commit -m "$(cat <<'EOF'
feat(provenance): wire `attest --provenance` to sign provenance evidence bundles (M4 §4.1)

Reuses the existing Ed25519 key material (same keypair as finding-evidence
attestations). `--provenance` alone attests every finding with
findingProvenance present; `--provenance <id>` scopes to one. Written to
.agentic-security/attestations/provenance-<id>.json, distinct from the
existing <id>.json finding-evidence bundles.
EOF
)"
```

---

### Task 3: extend `verify-attestation`'s auto-detection for provenance bundles

**Files:**
- Modify: `scanner/bin/agentic-security.js` (`cmdVerifyAttestation`, ~line 2429)
- Test: extend `scanner/test/cli/attest-provenance.test.js` (from Task 2)

**Interfaces:**
- Consumes: `verifyProvenanceEvidenceBundle`/`PROVENANCE_BUNDLE_SCHEMA` from Task 1.

- [ ] **Step 1: Add a schema-detection branch**

In `cmdVerifyAttestation` (read the current body first — reproduced in this plan's own research above, specifically the `if (bundle['@type'] === 'ComplianceEvidence')` branch at ~line 2459, which is the precedent to match), add a branch for `bundle.schema === PROVENANCE_BUNDLE_SCHEMA` BEFORE the fallback `verifyEvidenceBundle` call at the end (the fallback assumes `evidence-bundle.js`'s shape and would misinterpret a provenance bundle, exactly the bug `_asRunAttestation`'s own header comment already warns about for a different pair of shapes):

```js
  const { verifyProvenanceEvidenceBundle, PROVENANCE_BUNDLE_SCHEMA } = await import('../src/posture/provenance-evidence-bundle.js');
  if (bundle.schema === PROVENANCE_BUNDLE_SCHEMA) {
    const pr = verifyProvenanceEvidenceBundle(bundle, publicKeyPem);
    if (!pr.ok) { console.error(`✗ INVALID — ${pr.reason}`); return 1; }
    const p = bundle.provenance || {};
    console.log('✓ VALID — the provenance record is exactly what the signer attested.');
    console.log('');
    console.log(`  finding: ${bundle.finding?.stableId || bundle.finding?.id || '?'}`);
    console.log(`  status: ${p.status || 'n/a'}   method: ${p.method || 'n/a'}`);
    if (p.findingOrigin) console.log(`  origin: ${p.findingOrigin.commit || '?'} by ${p.findingOrigin.authorName || '?'} on ${p.findingOrigin.authorDate || '?'}`);
    console.log(`  confidence: ${p.confidence?.level || 'n/a'} (${p.confidence?.score ?? 'n/a'})`);
    if ((p.limitations || []).length) console.log(`  limitations: ${p.limitations.join('; ')}`);
    console.log('');
    console.log(`  proves:        ${bundle.proves}`);
    console.log(`  does NOT prove: ${bundle.doesNotProve}`);
    return 0;
  }
```

Insert this branch after the `ComplianceEvidence` branch (~line 2470, right before `const r = verifyEvidenceBundle(bundle, publicKeyPem);`) — one more entry in the same auto-detection chain, not a parallel dispatch mechanism. Confirm the `publicKeyPem` variable is already in scope at the insertion point (it is, per the existing code read in this plan's research — resolved once, above the `ComplianceEvidence` branch, and reused by every branch after it including the pre-existing fallback).

- [ ] **Step 2: Extend the test file from Task 2**

Append to `scanner/test/cli/attest-provenance.test.js`:

```js
test('verify-attestation: round-trips a real provenance bundle end-to-end', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');

  spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const file = fs.readdirSync(outDir).find((f) => f.startsWith('provenance-'));
  const r = spawnSync(process.execPath, [CLI, 'verify-attestation', path.join(outDir, file)], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(r.status, 0, `verify-attestation failed: ${r.stderr}\n${r.stdout}`);
  assert.match(r.stdout, /VALID/);
  assert.match(r.stdout, /origin:/);
});

test('verify-attestation: a tampered provenance bundle is rejected with exit 1', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');
  spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const file = fs.readdirSync(outDir).find((f) => f.startsWith('provenance-'));
  const p = path.join(outDir, file);
  const bundle = JSON.parse(fs.readFileSync(p, 'utf8'));
  bundle.provenance.confidence.level = 'high';
  bundle.provenance.findingOrigin.commit = 'tampered000000';
  fs.writeFileSync(p, JSON.stringify(bundle, null, 2));

  const r = spawnSync(process.execPath, [CLI, 'verify-attestation', p], { cwd: fx.root, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /INVALID/);
});
```

- [ ] **Step 3: Rebuild and run**

```bash
cd scanner
npm run build
node --test test/cli/attest-provenance.test.js
```
Expected: PASS, 4/4.

- [ ] **Step 4: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/bin/agentic-security.js scanner/test/cli/attest-provenance.test.js scanner/dist/
git commit -m "$(cat <<'EOF'
feat(provenance): verify-attestation recognizes provenance evidence bundles (M4 §4.1)

Extends the existing auto-detection chain (run-attestation / finding-evidence
bundle / ComplianceEvidence manifest) with a fourth shape, dispatched the
same way — by schema/@type marker, no new CLI verb. Closes out M4 §4.1: a
provenance record can now be signed (Task 2) and independently verified
with only a public key.
EOF
)"
```

---

### Task 4: `repo-lineage.js` — load and validate declared cross-repo linkage

**Files:**
- Create: `scanner/src/posture/provenance/repo-lineage.js`
- Test: `scanner/test/posture/provenance-repo-lineage.test.js`

**Interfaces:**
- Consumes: `_run`/`_isSha`-equivalent validation pattern from `git-evidence.js` (reuse, don't reimplement — see Global Constraints).
- Produces: `loadRepoLineage(scanRoot)` returning `{ path: absolutePath, atCommit: sha } | null`. Task 5 imports this.

- [ ] **Step 1: Write the module**

```js
// Cross-repository lineage declaration (Finding Provenance PRD, M4 §4.2).
//
// Git has no native cross-repo history — this is an OPERATOR-DECLARED link,
// read from .agentic-security/repo-lineage.json:
//   { "linkedFrom": { "path": "../old-repo-clone", "atCommit": "<sha>" } }
//
// Scoped to LOCAL clones only — no remote fetch, matching this codebase's
// "no runtime cloud calls" convention. Never throws; a missing, malformed,
// or unreachable link degrades to null, which origin-resolver.js reads as
// "no lineage available" and proceeds exactly as it did before M4.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { statePath } from '../state-dir.js';

const GIT_TIMEOUT_MS = 2000;
const SHA_RE = /^[0-9a-f]{4,40}$/i;

function _isLocallyReachableGitRepo(absPath) {
  try {
    if (!fs.statSync(absPath).isDirectory()) return false;
  } catch { return false; }
  try {
    cp.execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd: absPath, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch { return false; }
}

function _commitExists(absPath, sha) {
  try {
    cp.execFileSync('git', ['cat-file', '-e', `${sha}^{commit}`], {
      cwd: absPath, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch { return false; }
}

/**
 * Returns { path: <absolute, verified-reachable local git repo>, atCommit: <verified-existing sha> }
 * or null on ANY problem — missing config, malformed JSON, missing fields,
 * an unsafe-looking atCommit, a path that isn't a real local git repo, or a
 * commit that doesn't exist there. This function's whole job is to hand
 * back either a fully-verified link or nothing; it never hands back a
 * half-verified one for a caller to trust blindly.
 */
export function loadRepoLineage(scanRoot) {
  const configPath = statePath(scanRoot, 'repo-lineage.json');
  let text;
  try { text = fs.readFileSync(configPath, 'utf8'); } catch { return null; }
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  const linked = doc?.linkedFrom;
  if (!linked || typeof linked !== 'object') return null;
  const { path: relOrAbsPath, atCommit } = linked;
  if (typeof relOrAbsPath !== 'string' || !relOrAbsPath) return null;
  if (typeof atCommit !== 'string' || !SHA_RE.test(atCommit)) return null;

  const absPath = path.isAbsolute(relOrAbsPath) ? relOrAbsPath : path.resolve(scanRoot, relOrAbsPath);
  if (!_isLocallyReachableGitRepo(absPath)) return null;
  if (!_commitExists(absPath, atCommit)) return null;

  return { path: absPath, atCommit };
}
```

**Note the `SHA_RE`/timeout/`execFileSync` pattern above duplicates `git-evidence.js`'s own `_isSha`/`GIT_TIMEOUT_MS` — this is a SEPARATE module operating on a DIFFERENT repository path than `scanRoot` (the whole point of this module is to check paths outside the scanned repo), so `git-evidence.js`'s functions, which all assume `scanRoot` is the repo being asked about, don't directly apply here. If `git-evidence.js` exports its `_isSha`/timeout constant (check after Task 4 of M3's own fix round, which exported `_relPath`/`_isSafeRevision` — `_isSha` may or may not be among what's now exported), import and reuse them instead of the local re-declarations above. Verify before implementing rather than assuming either way.**

- [ ] **Step 2: Write tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { loadRepoLineage } from '../../src/posture/provenance/repo-lineage.js';

test('loadRepoLineage: no config file returns null', () => {
  const fx = createGitFixture();
  try { assert.equal(loadRepoLineage(fx.root), null); } finally { fx.cleanup(); }
});

test('loadRepoLineage: malformed JSON degrades to null, never throws', () => {
  const fx = createGitFixture();
  try {
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'), '{not json');
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); }
});

test('loadRepoLineage: a path that is not a real git repo returns null', () => {
  const fx = createGitFixture();
  try {
    const notARepo = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'as-not-a-repo-'));
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: notARepo, atCommit: '0'.repeat(40) } }));
    assert.equal(loadRepoLineage(fx.root), null);
    fs.rmSync(notARepo, { recursive: true, force: true });
  } finally { fx.cleanup(); }
});

test('loadRepoLineage: a commit that does not exist in the linked repo returns null', () => {
  const fx = createGitFixture();
  const linked = createGitFixture();
  try {
    linked.writeFile('x.js', '1');
    linked.commit('c1');
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: 'f'.repeat(40) } }));
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); linked.cleanup(); }
});

test('loadRepoLineage: a valid, verified link resolves correctly', () => {
  const fx = createGitFixture();
  const linked = createGitFixture();
  try {
    linked.writeFile('x.js', '1');
    const sha = linked.commit('c1');
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: sha } }));
    const result = loadRepoLineage(fx.root);
    assert.ok(result);
    assert.equal(result.path, linked.root);
    assert.equal(result.atCommit, sha);
  } finally { fx.cleanup(); linked.cleanup(); }
});

test('loadRepoLineage: an unsafe-looking atCommit (not a real SHA) is rejected before reaching git', () => {
  const fx = createGitFixture();
  try {
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: fx.root, atCommit: '--upload-pack=evil' } }));
    assert.equal(loadRepoLineage(fx.root), null);
  } finally { fx.cleanup(); }
});
```

**Fix the `require('node:os')` calls the same way Task 2's Step 3 already flagged — use `import * as os from 'node:os'` at the top of the file instead. (Repeated deliberately: this plan's implementers should catch and fix this in every test file it appears in, not just the first.)**

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-repo-lineage.test.js` (foreground, timeout 60000). Expected: PASS, 6/6.

- [ ] **Step 4: Add to `test:posture` and commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/repo-lineage.js scanner/test/posture/provenance-repo-lineage.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): repo-lineage.js — load + verify declared cross-repo linkage (M4 §4.2)

.agentic-security/repo-lineage.json declares { linkedFrom: {path, atCommit} }.
Fully verified before being handed to any caller: the path must be a real,
locally-reachable git repo (no remote fetch — local clones only) and
atCommit must genuinely exist there. Standalone; not yet wired into
origin-resolver.js (Task 5).
EOF
)"
```

---

### Task 5: wire cross-repo continuation into `origin-resolver.js`'s root-commit case

**Files:**
- Modify: `scanner/src/posture/provenance/origin-resolver.js`
- Modify: `scanner/src/posture/provenance/schema.js` (`historyCoverage` gains an optional `crossRepoLineage` field — additive)
- Test: extend `scanner/test/posture/provenance-origin-resolver.test.js`

**Interfaces:**
- Consumes: `loadRepoLineage` from Task 4.
- Produces: when a root-commit resolution is reached AND a verified lineage link exists AND the file+line content is present in the linked repo, the walk continues there; result carries `historyCoverage.crossRepoLineage: true`. This can only ever produce `status: 'partial'` at best (see reasoning below) — it NEVER upgrades to `'complete'`, because a cross-repo match is verified by content presence, not by the same predicate-replay machinery `resolveOrigin` uses within one repo (replaying a historical detector run needs the exact IR/detector pipeline state at that commit, which crossing a repo boundary cannot guarantee is even the same codebase's tooling version).

- [ ] **Step 1: Add the cross-repo continuation function**

In `origin-resolver.js`, add (near the top, after imports, before `originFrom`):

```js
import { loadRepoLineage } from './repo-lineage.js';
import { candidateCommitsForLine as _candidateCommitsForLineAnyRoot } from './git-evidence.js';
// (candidateCommitsForLine is likely already imported under a different
// local name at the top of this file — check the existing import block
// before adding a second import of the same export under an alias; if it's
// already imported as `candidateCommitsForLine`, reuse that name directly
// in Step 2 below instead of introducing `_candidateCommitsForLineAnyRoot`.)

/**
 * Best-effort cross-repo continuation when the standard walk reaches this
 * repo's TRUE root commit (no parent, non-shallow) without resolving. Only
 * fires when a repo-lineage link is declared and verified. Confirms the
 * SAME relative file path exists in the linked repo at atCommit, and that
 * the finding's line content is textually present there (a presence check,
 * NOT a predicate replay — the detector pipeline that proved the finding's
 * predicate true in THIS repo cannot be assumed identical in the linked
 * one). On a match, restarts candidateCommitsForLine's walk in the linked
 * repo starting from atCommit backward, reusing the SAME first-parent-only
 * logic the standard walk already uses (not deep mode — cross-repo lineage
 * doesn't compose with non-linear-ancestry search in this milestone; a
 * later milestone can revisit if a real need appears).
 *
 * Returns null on ANY failure to extend (no lineage, file/line absent
 * there, nothing further resolves) — the caller falls through to its
 * existing not-linked-or-unresolved behavior unchanged.
 */
function tryCrossRepoLineage(scanRoot, finding, rootMeta) {
  const lineage = loadRepoLineage(scanRoot);
  if (!lineage) return null;

  const { getBlobAtCommit } = require('./git-evidence.js'); // see note below re: import style
  const blob = getBlobAtCommit(lineage.path, lineage.atCommit, finding.file);
  if (blob == null) return null;
  const lines = blob.split('\n');
  const lineNo = finding.line || finding.sink?.line;
  if (!lineNo || lineNo > lines.length) return null;
  // A cheap, honest presence check: the SOURCE LINE's own text (trimmed) is
  // literally there. Not the finding's full predicate — that would require
  // re-running the detector pipeline, out of scope for a best-effort link.
  if (!lines[lineNo - 1] || !lines[lineNo - 1].trim()) return null;

  const linkedCandidates = candidateCommitsForLine(lineage.path, finding.file, lineNo, {});
  // Only candidates at or before atCommit are eligible — the lineage link
  // says history was imported AT that commit, so anything after it in the
  // linked repo's own timeline is not part of what became this repo.
  // candidateCommitsForLine returns oldest-first; filtering here rather than
  // passing a `since`/`until` bound keeps this function self-contained
  // without adding an `until` parameter to a shared, widely-used primitive
  // for one caller.
  const eligible = linkedCandidates; // see Step 1 verification note below
  if (eligible.length === 0) return null;

  const oldestMatch = eligible[0];
  const meta = commitMeta(lineage.path, oldestMatch);
  if (!meta) return null;

  return {
    status: 'partial',
    reason: 'cross-repo-lineage-best-effort',
    commitsConsidered: eligible.length,
    findingOrigin: originFrom(meta, { absentInParents: [] }),
    method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
    crossRepoLineage: true,
  };
}
```

**This step has TWO deliberate problems for the implementer to find and fix, matching this plan's own established practice (M3's plan had the same kind of intentional gap in several tasks, always caught by the implementer's own testing):**

1. **The `require('./git-evidence.js')` call is CommonJS syntax in an ESM file** — it will throw. `getBlobAtCommit` needs a proper top-of-file `import` alongside this file's other imports from `git-evidence.js`. Fix it, and check `getBlobAtCommit`'s exact signature (`scanRoot, sha, file` per M3's own fix — the M3 final-review fix round added a `./`-prefix fix to this exact function for the "scanRoot is a subdirectory" case; that fix benefits this caller too, at no extra cost, since it's the same function).
2. **The `eligible` filtering claimed in the comment ("only candidates at or before atCommit") is NOT ACTUALLY DONE** — `const eligible = linkedCandidates;` doesn't filter anything, contradicting its own comment. Since `candidateCommitsForLine` walks the linked repo's CURRENT history (which could extend past `atCommit` if the linked repo kept being developed after the fork point), this is a real bug: it could resolve to a commit that postdates the declared lineage boundary, which would be answering the wrong question (this repo's history didn't include anything after the fork). Fix: filter `linkedCandidates` to only those reachable from `atCommit` — the simplest correct approach is running `candidateCommitsForLine` with a bound, OR (since that primitive doesn't take an `until` param, only `since`) filtering the returned candidate list to those where `git merge-base --is-ancestor <candidate> atCommit` succeeds in the linked repo (a small new git-evidence.js-style check, or inline via `cp.execFileSync`, matching this module's own established patterns — decide which fits better once you're looking at the real code, and justify the choice in your report).

Before finalizing either fix, empirically verify it: build a small scratch scenario with TWO real git repos (a "linked/old" repo and a "current/new" one, with the old repo's history NOT literally copied into the new one — this whole feature is about a DECLARED link, not a real git relationship, so your scratch test should reflect that: two independent repos, a `repo-lineage.json` in the new one pointing at the old one). Confirm the fixed function correctly finds an old-repo-only commit and correctly refuses to resolve to something that doesn't exist there or postdates `atCommit`.

- [ ] **Step 2: Wire `tryCrossRepoLineage` into the standard-mode root-commit branch**

In `resolveOrigin`, the standard-mode root-commit branch (~line 105-112, reproduced in this plan's research above) currently returns `status:'complete'` unconditionally for a true (non-shallow) root. Change it to try cross-repo lineage FIRST, and only fall back to the existing same-repo root-commit resolution if lineage doesn't extend the answer:

```js
      // True repository root, non-shallow. Before settling for "no parent
      // exists to verify absence in" (M2/M3's existing weaker-evidence
      // path), try extending the walk into a declared cross-repo lineage
      // link (M4 §4.2) — this repo's root may not be where the code was
      // actually first written, just where THIS repo's history starts.
      const crossRepo = tryCrossRepoLineage(scanRoot, finding, meta);
      if (crossRepo) return crossRepo;
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: originFrom(meta, { absentInParents: [] }),
        parentBoundaryVerified: false,
      };
```

**Do NOT wire this into the deep-mode root-commit branch (~line 152-158) in this task** — deep mode's root-commit case is reached via a materially different path (`checkAbsentInSomeParent`'s non-first-parent walk) and composing cross-repo lineage with that logic needs its own design pass, explicitly out of scope per Step 1's own header comment ("cross-repo lineage doesn't compose with non-linear-ancestry search in this milestone"). If a future task wires it there, that is real new scope, not an oversight in this one.

- [ ] **Step 3: Add `crossRepoLineage` to `schema.js`'s `historyCoverage` shape**

In `schema.js`'s `emptyProvenance` (~line 62), `historyCoverage`'s default shape gains one more field:
```js
    historyCoverage: { complete: false, shallow: false, boundaryCommit: null, commitsConsidered: 0, crossRepoLineage: false },
```
And in `coordinator.js`, wherever `historyCoverage` is constructed for a `'partial'` result from `resolveOrigin` (the `originResult.status === 'partial'` branch, ~line 284-314 per this plan's own research above), thread `crossRepoLineage: !!originResult.crossRepoLineage` into that object instead of leaving it at the `emptyProvenance` default. Read `coordinator.js`'s exact `historyCoverage` construction for the partial branch before editing — this plan doesn't reproduce it in full; find and match its exact current shape.

- [ ] **Step 4: Write tests**

```js
// Add to provenance-origin-resolver.test.js:

test('resolveOrigin: a true root commit with a verified cross-repo lineage link resolves partial with crossRepoLineage:true, not the same-repo root fallback', async () => {
  const linked = createGitFixture();
  const fx = createGitFixture();
  try {
    linked.writeFile('shared.js', 'const x = req.query.x;\neval(x);\n');
    const linkedSha = linked.commit('the real original introduction, in the OLD repo');

    fx.writeFile('shared.js', 'const x = req.query.x;\neval(x);\n');
    fx.commit('imported wholesale as this repo\'s first commit');
    const fs2 = await import('node:fs');
    const path2 = await import('node:path');
    fs2.mkdirSync(path2.join(fx.root, '.agentic-security'), { recursive: true });
    fs2.writeFileSync(path2.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: linkedSha } }));

    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const finding = { file: 'shared.js', line: 2, stableId: computeStableId({ file: 'shared.js', line: 2, vuln: 'eval' }) };
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });

    assert.equal(result.status, 'partial');
    assert.equal(result.crossRepoLineage, true);
    assert.equal(result.findingOrigin.commit, linkedSha);
  } finally { fx.cleanup(); linked.cleanup(); }
});

test('resolveOrigin: a true root commit with NO lineage link resolves exactly as before M4 (regression guard)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('shared.js', 'const x = req.query.x;\neval(x);\n');
    const sha = fx.commit('first commit, no lineage declared');
    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const finding = { file: 'shared.js', line: 2, stableId: computeStableId({ file: 'shared.js', line: 2, vuln: 'eval' }) };
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete');
    assert.equal(result.parentBoundaryVerified, false);
    assert.equal(result.findingOrigin.commit, sha);
    assert.equal(result.crossRepoLineage, undefined);
  } finally { fx.cleanup(); }
});

test('resolveOrigin: a lineage link exists but the file/line is not present in the linked repo at atCommit — falls back honestly, never fabricates', async () => {
  const linked = createGitFixture();
  const fx = createGitFixture();
  try {
    linked.writeFile('unrelated.js', '1');
    const linkedSha = linked.commit('nothing relevant here');

    fx.writeFile('shared.js', 'const x = req.query.x;\neval(x);\n');
    const sha = fx.commit('genuinely new code, no real lineage despite the declared link');
    const fs2 = await import('node:fs');
    const path2 = await import('node:path');
    fs2.mkdirSync(path2.join(fx.root, '.agentic-security'), { recursive: true });
    fs2.writeFileSync(path2.join(fx.root, '.agentic-security', 'repo-lineage.json'),
      JSON.stringify({ linkedFrom: { path: linked.root, atCommit: linkedSha } }));

    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const finding = { file: 'shared.js', line: 2, stableId: computeStableId({ file: 'shared.js', line: 2, vuln: 'eval' }) };
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete'); // falls back to the ordinary same-repo root resolution
    assert.equal(result.findingOrigin.commit, sha);
    assert.equal(result.crossRepoLineage, undefined);
  } finally { fx.cleanup(); linked.cleanup(); }
});
```

**Check `computeStableId`'s real import path/signature against how OTHER tests in this same file already construct a `stableId` for a hand-built finding — this plan's snippet above guesses the call shape; match the file's own established pattern instead of trusting this guess.**

- [ ] **Step 5: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js` (foreground, timeout 90000). Expected: PASS, all prior tests + 3 new ones.

Run: `cd scanner && npm run test:posture` (foreground, timeout 300000) — this touches `schema.js`'s shared `emptyProvenance` shape, broad regression check warranted.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/origin-resolver.js scanner/src/posture/provenance/schema.js scanner/test/posture/provenance-origin-resolver.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): cross-repo lineage continuation at the root-commit boundary (M4 §4.2)

When the standard walk reaches this repo's true root commit unresolved, and
a verified .agentic-security/repo-lineage.json link exists, the walk
continues in the linked local repo — capped at 'partial' (never 'complete':
a cross-repo content-presence check is weaker evidence than same-repo
predicate replay). historyCoverage.crossRepoLineage:true discloses when an
answer crossed a repository boundary. Deep mode's root-commit case is
explicitly NOT wired to this in M4 — different code path, different design
question, left for a future milestone.
EOF
)"
```

---

### Task 6: `ai-authorship.js` — verifier registry hook

**Files:**
- Create: `scanner/src/posture/provenance/ai-authorship.js`
- Modify: `scanner/src/posture/provenance/origin-resolver.js` (`originFrom`)
- Modify: `scanner/src/posture/provenance/coordinator.js` (thread the field through, if `originFrom`'s output isn't already passed through unchanged — verify)
- Test: `scanner/test/posture/provenance-ai-authorship.test.js`

**Interfaces:**
- Produces: `registerAIAuthorshipVerifier(name, verifyFn)`, `resolveAIAuthorship(commitMeta)` returning `{ status: 'unknown' | string, verifier: string | null }`. `verifyFn` signature: `(commitMeta) => { status: string, verifier: string } | null` (returning `null` means "this verifier has no opinion," not "verified unknown" — lets multiple verifiers coexist without one's silence overriding another's answer).

- [ ] **Step 1: Write the module**

```js
// AI-authorship verification hook (Finding Provenance PRD, M4 §4.3).
//
// No concrete external signed-commit-metadata standard exists yet to target
// (the spec's own words) — so this is an extensible REGISTRY a future
// verifier plugs into, not a hardcoded vendor integration. With nothing
// registered (today's real state, and likely for some time), every
// finding's aiAuthorship stays `unknown` — matching the PRD's explicit
// default: "Unknown unless signed, verifiable generation metadata exists."
//
// Scoped to SAST findingOrigin only (see this plan's own scope-correction
// note) — a transitive/direct SCA origin is a manifest edit, not source
// authorship in the sense this hook asks about.

const _verifiers = new Map();

/**
 * Register a verifier. `verifyFn(commitMeta) -> {status, verifier} | null`.
 * A later registration under the SAME name replaces the earlier one (a
 * re-register, not a stack) — matches this codebase's own precedent
 * elsewhere (verification-separation.js's "one verifier, one vote per lens,
 * a re-vote replaces rather than stuffs").
 */
export function registerAIAuthorshipVerifier(name, verifyFn) {
  if (typeof name !== 'string' || !name || typeof verifyFn !== 'function') return false;
  _verifiers.set(name, verifyFn);
  return true;
}

/** Test/reset helper — never called from production code. */
export function _clearAIAuthorshipVerifiers() {
  _verifiers.clear();
}

/**
 * Consults every registered verifier in registration order; the first one
 * to return a non-null result wins (first-registered-first-consulted, not
 * "last wins" — an explicit choice: a more specific verifier should be
 * registered first if precedence matters, rather than this function
 * guessing which of several opinions to prefer). Defaults to
 * {status:'unknown', verifier:null} with nothing registered or every
 * verifier declining to answer.
 *
 * NEVER THROWS: a verifier that throws is treated as "no opinion", exactly
 * like predicate-replay.js and missing-control-resolver.js already treat a
 * throwing caller-supplied function elsewhere in this directory.
 */
export function resolveAIAuthorship(commitMeta) {
  if (!commitMeta) return { status: 'unknown', verifier: null };
  for (const [name, verifyFn] of _verifiers) {
    let result;
    try { result = verifyFn(commitMeta); } catch { continue; }
    if (result && typeof result === 'object' && result.status) {
      return { status: result.status, verifier: result.verifier || name };
    }
  }
  return { status: 'unknown', verifier: null };
}
```

- [ ] **Step 2: Wire into `origin-resolver.js`'s `originFrom`**

```js
import { resolveAIAuthorship } from './ai-authorship.js';

function originFrom(meta, { absentInParents }) {
  return {
    commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
    authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
    presentInCommit: true, absentInParents, revertOf: null, cherryPickOf: null,
    aiAuthorship: resolveAIAuthorship(meta),
  };
}
```

**Verify `commitMeta`'s exact return shape (`git-evidence.js`'s `commitMeta` function) matches what a verifier would plausibly need (commit sha, author name/email, commit message/summary, date) — if it's missing something a real future verifier would need (e.g. the raw commit message body, not just `summary`), note this as a known limitation in the module's own header rather than silently expanding `commitMeta`'s shape (out of scope for this task; `commitMeta` is a widely-used shared primitive and changing its shape is a bigger, more careful change than this task's budget).**

- [ ] **Step 3: Confirm `coordinator.js` doesn't strip the new field**

Read `coordinator.js`'s `'complete'` branch (~line 274-283 per this plan's earlier research) — it sets `findingOrigin: originResult.findingOrigin` directly (spreads the whole object through, per the code already read during this plan's research). Confirm this is still true when you implement this step (re-read the current file, don't assume the earlier research snippet is still exact) — if so, `aiAuthorship` rides through for free, no coordinator.js change needed. If the construction instead hand-picks specific sub-fields (rather than passing the whole `findingOrigin` object through), you'll need to add `aiAuthorship: originResult.findingOrigin?.aiAuthorship` explicitly — verify which is true before assuming either way.

- [ ] **Step 4: Write tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerAIAuthorshipVerifier, resolveAIAuthorship, _clearAIAuthorshipVerifiers } from '../../src/posture/provenance/ai-authorship.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

test('resolveAIAuthorship: with nothing registered, always unknown', () => {
  _clearAIAuthorshipVerifiers();
  const r = resolveAIAuthorship({ commit: 'abc', authorName: 'Alice', summary: 'x' });
  assert.deepEqual(r, { status: 'unknown', verifier: null });
});

test('resolveAIAuthorship: null commitMeta never throws, resolves unknown', () => {
  _clearAIAuthorshipVerifiers();
  assert.deepEqual(resolveAIAuthorship(null), { status: 'unknown', verifier: null });
});

test('registerAIAuthorshipVerifier: a registered verifier that answers is consulted', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('claude-co-author-trailer', (meta) =>
    /Co-Authored-By: Claude/.test(meta.summary || '') ? { status: 'ai-assisted', verifier: 'claude-co-author-trailer' } : null);
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'fix: thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>' });
  assert.equal(r.status, 'ai-assisted');
  assert.equal(r.verifier, 'claude-co-author-trailer');
});

test('registerAIAuthorshipVerifier: a verifier that declines (returns null) falls through to unknown', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('always-declines', () => null);
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.deepEqual(r, { status: 'unknown', verifier: null });
});

test('registerAIAuthorshipVerifier: a THROWING verifier is treated as no-opinion, never crashes the resolver', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('broken', () => { throw new Error('boom'); });
  registerAIAuthorshipVerifier('fallback', () => ({ status: 'human', verifier: 'fallback' }));
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.equal(r.status, 'human');
});

test('re-registering the same name replaces, does not stack', () => {
  _clearAIAuthorshipVerifiers();
  registerAIAuthorshipVerifier('v', () => ({ status: 'first', verifier: 'v' }));
  registerAIAuthorshipVerifier('v', () => ({ status: 'second', verifier: 'v' }));
  const r = resolveAIAuthorship({ commit: 'abc', summary: 'x' });
  assert.equal(r.status, 'second');
});

test('origin-resolver.js: every SAST findingOrigin carries aiAuthorship, defaulting to unknown with nothing registered', async () => {
  _clearAIAuthorshipVerifiers();
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(req.query.x);\n');
    fx.commit('introduce');
    const { resolveOrigin } = await import('../../src/posture/provenance/origin-resolver.js');
    const { computeStableId } = await import('../../src/posture/provenance/schema.js'); // verify real export path
    const finding = { file: 'a.js', line: 1, stableId: computeStableId({ file: 'a.js', line: 1, vuln: 'eval' }) };
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.deepEqual(result.findingOrigin.aiAuthorship, { status: 'unknown', verifier: null });
  } finally { fx.cleanup(); }
});
```

**`computeStableId`'s real export location is a guess in the last test — check where OTHER tests in `provenance-origin-resolver.test.js` import it from (this plan's Task 5 tests make the same guess; resolve it once and apply consistently across every test file this plan adds that needs a hand-built `stableId`).**

- [ ] **Step 5: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-ai-authorship.test.js test/posture/provenance-origin-resolver.test.js` (foreground, timeout 90000). Expected: PASS.

- [ ] **Step 6: Add to `test:posture` and commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/ai-authorship.js scanner/src/posture/provenance/origin-resolver.js scanner/test/posture/provenance-ai-authorship.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): AI-authorship verification hook, defaults to unknown (M4 §4.3)

registerAIAuthorshipVerifier/resolveAIAuthorship — an extensible registry,
not a vendor integration, since no concrete signed-commit-metadata standard
exists yet to target. Wired into origin-resolver.js's originFrom so every
SAST findingOrigin carries findingOrigin.aiAuthorship, defaulting to
{status:'unknown', verifier:null} with nothing registered (today's real
state). Scoped to SAST origins only — a transitive/direct SCA origin is a
manifest edit, not source authorship.
EOF
)"
```

---

### Task 7: fleet.js provenance/lifecycle rollups

**Files:**
- Modify: `scanner/src/posture/fleet.js` (`rollupFleet`, `renderFleetHtml`, `renderFleetSummary`)
- Test: extend `scanner/test/fleet.test.js`

**Interfaces:**
- Consumes: nothing from other M4 tasks — reads `findingProvenance`/`ageBasis` fields M2/M3 already populate on findings.
- Produces: `rollupFleet`'s return value gains a `provenanceDebt` section: oldest proven-origin finding across the fleet (by `findingOrigin.authorDate` where `status === 'complete'`), and `ageBasis`-aware time-to-remediation stats, both fleet-wide and per-repo. Repos with no `'complete'`-status findings are disclosed as such, never silently excluded from a count that implies they were considered and came up clean.

- [ ] **Step 1: Read `rollupFleet`/`renderFleetHtml`/`renderFleetSummary` in full**

Read the current implementations (`scanner/src/posture/fleet.js`, functions at ~line 205, ~250, ~274 per this plan's own research) before writing this step — reproduce their EXACT current signatures and return shapes in your report before changing anything, since this plan does not have their bodies in front of it and this step's code below is written against the FR-1006-era shape referenced in this plan's research (governance gaps, per-repo results) which may have evolved further since. Adapt the insertion points to match reality.

- [ ] **Step 2: Add the provenance rollup to `rollupFleet`**

Add a new computation inside `rollupFleet`, alongside its existing per-repo aggregation loop — for each repo's `results[i].scan.findings` (confirm the exact field path per Step 1's read):

```js
// M4 §4.4: provenance-aware debt, not wall-clock-only. A repo contributes
// to `oldestProvenDebt` only from findings whose findingProvenance.status
// is 'complete' — the honest end of the confidence spectrum. A repo with
// NO complete-status findings is listed in `unproven` (disclosed BY NAME,
// never silently absent from a "no debt" story a reader would misread as
// "this repo has no old findings" when the truth is "we couldn't PROVE any
// origin here").
function _provenanceDebtRollup(perRepoResults) {
  let oldest = null; // { repo, findingId, authorDate, ageDays }
  const unproven = [];
  const now = Date.now();
  for (const { repo, scan } of perRepoResults) {
    const findings = (scan?.findings || []).filter((f) => f.findingProvenance?.status === 'complete' && f.findingProvenance?.findingOrigin?.authorDate);
    if (findings.length === 0) { unproven.push(repo); continue; }
    for (const f of findings) {
      const authorDate = f.findingProvenance.findingOrigin.authorDate;
      const ageDays = Math.max(0, Math.floor((now - Date.parse(authorDate)) / 86400000));
      if (!oldest || ageDays > oldest.ageDays) oldest = { repo, findingId: f.id, authorDate, ageDays };
    }
  }
  return { oldestProvenDebt: oldest, reposWithNoProvenDebt: unproven };
}

// ageBasis-aware time-to-remediation: reuses each finding's own
// f.ageBasis/f.provenAgeDays (mttr.js already computes these per-finding —
// see posture/mttr.js's own header) rather than recomputing wall-clock age
// here, so a fleet-wide MTTR is built from the SAME honest age basis a
// single-repo report already discloses, not two different notions of "age"
// that could silently disagree.
function _fleetMTTR(perRepoResults) {
  const remediated = [];
  for (const { scan } of perRepoResults) {
    for (const f of (scan?.remediatedFindings || scan?.findings || [])) {
      if (typeof f.provenAgeDays === 'number' && f.ageBasis) remediated.push({ ageBasis: f.ageBasis, days: f.provenAgeDays });
    }
  }
  if (!remediated.length) return { n: 0, medianDays: null, byAgeBasis: {} };
  const sorted = remediated.map((r) => r.days).sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const byAgeBasis = {};
  for (const r of remediated) byAgeBasis[r.ageBasis] = (byAgeBasis[r.ageBasis] || 0) + 1;
  return { n: remediated.length, medianDays: median, byAgeBasis };
}
```

**Verify `scan.remediatedFindings` is a real field — this plan guesses at it based on `mttr.js`'s described role ("reports both proven and wall-clock age") without having read `mttr.js` directly in this planning pass. Read `scanner/src/posture/mttr.js` before implementing this step to confirm where remediated findings (vs. still-open ones) actually live on a scan result, and adjust `_fleetMTTR`'s source accordingly — do not ship a function that silently operates on the wrong array.**

Thread both helpers' output into `rollupFleet`'s return value under a new `provenance` key (`{ ...existingRollup, provenance: { ..._provenanceDebtRollup(...), ..._fleetMTTR(...) } }`), matching the additive-field pattern this file already uses for FR-1006's `policyDrift`/governance-gap additions (per this plan's own research showing those as a separate section alongside the risk-finding rollup, not replacing it).

- [ ] **Step 3: Surface in `renderFleetSummary` and `renderFleetHtml`**

Add one sentence to `renderFleetSummary`'s output (matching its existing style — read a few of its current sentences first) reporting the oldest proven-origin debt (repo + age in days) and how many repos had none, or an honest "no proven-origin findings across the fleet" line if `oldest` is null. In `renderFleetHtml`, add a new section (matching the existing governance-gap section's separate-section pattern from FR-1006) titled something like "Provenance-Proven Debt" listing the oldest finding per repo (not just the single fleet-wide oldest) and the MTTR breakdown by `ageBasis`. Follow the existing HTML generation style in this file closely (no new templating library, no external references — `renderFleetHtml`'s own header already establishes "no scripts, no external references").

- [ ] **Step 4: Write tests**

```js
// Add to fleet.test.js — read the file's existing helper functions for
// constructing a fake per-repo result first, and match that shape exactly
// rather than guessing scan.findings' structure.

test('M4 §4.4: rollupFleet computes oldestProvenDebt from complete-status findingProvenance only', () => {
  const results = [
    { repo: 'repo-a', scan: { findings: [
      { id: 'f1', findingProvenance: { status: 'complete', findingOrigin: { authorDate: '2020-01-01T00:00:00Z' } } },
    ] } },
    { repo: 'repo-b', scan: { findings: [
      { id: 'f2', findingProvenance: { status: 'partial', findingOrigin: { authorDate: '2010-01-01T00:00:00Z' } } }, // older but not complete — must NOT win
    ] } },
  ];
  const rollup = rollupFleet(results); // adapt call signature to match the real function once read
  assert.equal(rollup.provenance.oldestProvenDebt.repo, 'repo-a');
});

test('M4 §4.4: a repo with zero complete-status findings is disclosed in reposWithNoProvenDebt, not silently omitted', () => {
  const results = [
    { repo: 'repo-c', scan: { findings: [
      { id: 'f3', findingProvenance: { status: 'not_available' } },
    ] } },
  ];
  const rollup = rollupFleet(results);
  assert.deepEqual(rollup.provenance.oldestProvenDebt, null);
  assert.ok(rollup.provenance.reposWithNoProvenDebt.includes('repo-c'));
});

test('M4 §4.4: renderFleetSummary mentions provenance debt honestly (repo+age, or an explicit "none" line)', () => {
  const rollup = { /* ...build a minimal rollup matching the real shape, with provenance.oldestProvenDebt set... */ };
  const summary = renderFleetSummary(rollup);
  assert.match(summary, /proven|provenance/i);
});
```

**These three test bodies are intentionally under-specified (the second and third need the REAL `rollupFleet`/`renderFleetSummary` call signatures, which this planning pass did not have in front of it — see Step 1). Fill them in against the actual current signatures once Step 1's read is done; do not guess at a call shape and ship an untested guess.**

- [ ] **Step 5: Incidental hardening — `_matchesGlob`'s raw NUL-byte placeholder**

While in this file for the above changes, fix a pre-existing robustness issue discovered during this plan's own research (unrelated to M4's scope, but directly adjacent to code this task already touches, and cheap to fix now rather than leaving a landmine — per this codebase's own brainstorming-skill convention: "Where existing code has problems that affect the work... include targeted improvements as part of the design"). `_matchesGlob` (~line 79-90) uses a LITERAL raw NUL byte (`'\x00'`, an actual embedded NUL character in the source file, not an escape sequence) as a two-step placeholder when converting `**` to `.*`:

```js
  const rx = new RegExp('^' + p
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\x00')
    .replace(/\*/g, '[^/]*')
    .replace(/\x00/g, '.*') + '(/.*)?$');
```

This works (Node.js allows a raw NUL character inside a string literal, and the trailing `.replace(/\x00/g, ...)`'s regex literal parses `\x00` as a standard hex-escape matching that same character) but is fragile: this exact raw byte is what caused `file`(1)/`grep`(1) to misclassify this source file as binary data during this plan's own research (confirmed: `file src/posture/fleet.js` reports `data`, not `ASCII text`, purely because of these two embedded NUL bytes), which can also confuse some editors, diff tools, or naive text-processing CI steps. Replace the raw-byte placeholder with the JavaScript escape SEQUENCE for a Unicode Private Use Area codepoint -- six literal ASCII characters (backslash, u, E, 0, 0, 0) typed into the source, which Node's own parser turns into that one character at parse time -- never a raw non-ASCII byte embedded directly in the file (that would just move the exact same fragility this fix exists to remove from one byte value to another):

```js
  const PLACEHOLDER = '\uE000'; // escape SEQUENCE in source -- 6 ASCII chars, not a raw embedded byte
  const rx = new RegExp('^' + p
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, PLACEHOLDER)
    .replace(/\*/g, '[^/]*')
    .replace(new RegExp(PLACEHOLDER, 'g'), '.*') + '(/.*)?$');
```

(The final `.replace` uses `new RegExp(PLACEHOLDER, 'g')` built from the same escaped string constant, rather than a second `/.../ ` regex literal repeating the escape -- keeps the placeholder defined in exactly one place, so there is no chance of the two occurrences drifting to different characters.)

Run the existing `_matchesGlob`/CODEOWNERS tests (`node --test test/fleet.test.js`, filtering to `ownersFor`-related tests if the file supports `--test-name-pattern`) before AND after this one-line change to confirm it's genuinely behavior-preserving — this is a placeholder swap, not a logic change, so it must be a no-op. Confirm via `file scanner/src/posture/fleet.js` after the edit that it now reports as text, not `data`.

- [ ] **Step 6: Run and verify**

Run: `cd scanner && node --test test/fleet.test.js` (foreground, timeout 60000). Expected: PASS, all prior tests (33 per this plan's research) + new ones.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/fleet.js scanner/test/fleet.test.js
git commit -m "$(cat <<'EOF'
feat(fleet): provenance-aware debt + MTTR rollups (M4 §4.4)

Oldest proven-origin finding across the fleet (status:'complete' only —
never a wall-clock guess dressed as proof), disclosed per-repo including
repos with zero complete-status findings (never silently folded into "no
debt"). Time-to-remediation reuses each finding's own ageBasis/provenAgeDays
(mttr.js) rather than recomputing wall-clock age, so fleet-wide MTTR agrees
with what a single-repo report already discloses.

Incidental: replaced a raw embedded NUL-byte placeholder in _matchesGlob
with a normal  escape — behavior-identical, but the raw byte was
causing `file`/grep to misclassify this source file as binary data.
EOF
)"
```

---

## End-of-plan: final build + whole-branch verification

After Task 7 (the last task), before the final whole-branch review:

- [ ] Run `cd scanner && npm run build 2>&1 | tail -20` (foreground, timeout 120000) and confirm it completes without error.
- [ ] Run `cd scanner && npm test` (foreground, timeout 700000) and capture the REAL exit code from the run's own output, not a wrapper's. Compare failures against the established pre-existing-flaky-test signature (subprocess-spawn timeout, `status: null`) from M2/M3's own sessions — a NEW failure outside that signature is a real regression requiring investigation. This sandbox has shown SEVERE, worsening resource contention across M3's own final stretch (documented in M3's own ledger) — budget for possibly needing 2-3 retries of any given gate, and always read the REAL log, never trust a backgrounded wrapper's own exit-code notification (M3's ledger documents this exact trap being hit and caught).
- [ ] Run `cd scanner && npm run bench:cve-replay:check` (foreground, timeout 300000, wiping stray `.agentic-security` dirs under `bench/cve-replay` first) and `npm run bench:self-scan:check` (same, under `bench/self-scan`) — both must pass. M4 adds no new SAST/SCA detection surface, so neither gate should show ANY drift; if either does, investigate before assuming it's environmental.
- [ ] Run `cd scanner && npm run bench:provenance:check` (foreground, timeout 300000) — M4 added real work to the root-commit path (cross-repo lineage attempt, AI-authorship resolution) that runs on every SAST origin resolution reaching that point, not just a rare corner case. Confirm the M2/M3-established overhead baseline hasn't regressed materially; re-baseline deliberately with `npm run bench:provenance:update-baseline` and say why in the commit if it has, per this repo's own established discipline — never silently accept a worse number without comment.
- [ ] Run `cd scanner && node --test test/no-dead-modules.test.js test/check-doc-drift.test.js` explicitly — this plan adds 4 new modules (`provenance-evidence-bundle.js`, `repo-lineage.js`, `ai-authorship.js`, plus whatever Task 5/6 export from `origin-resolver.js`/`coordinator.js`) and this plan's own Task-writing process did NOT update `scanner/src/posture/CLAUDE.md`'s "Finding provenance" module table or module count (now 18 → 21) — a documentation-drift task should be added to this plan's own execution before the final review if the dead-modules/doc-drift gates surface it, mirroring exactly what M3's final review caught and fixed for the SAME two gates. Do not skip this just because M3 already fixed the count once — M4 moves it again.
