// Shared SYNTHETIC fixtures for the portfolio suites (X-701 to X-705). Not a test file.
// Nothing here describes a real release or portfolio: every manifest built here carries `synthetic: true`.
import crypto from 'node:crypto';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { buildManifest } from '../../src/posture/portfolio/manifest.js';
import { exportBundle } from '../../src/posture/portfolio/bundle.js';
import { planPortfolio } from '../../src/posture/portfolio/work-units.js';

export const COMMIT = 'a'.repeat(40);
export const DEP_COMMIT = 'b'.repeat(40);
export const sha = (s) => `sha256:${crypto.createHash('sha256').update(s).digest('hex')}`;

export const RECEIPTS = [
  { id: 'vrec:0001', content: { outcome: 'confirmed', note: 'synthetic receipt one' } },
  { id: 'vrec:0002', content: { outcome: 'refuted', note: 'synthetic receipt two' } },
];

export function manifestFacts(over = {}) {
  const policyDigest = sha('policy-v1');
  const receipts = RECEIPTS.map((r) => ({ id: r.id, digest: digestOf(r.content), repository: 'app', commit: COMMIT }));
  return {
    synthetic: true,
    subject: { repository: 'app', commit: COMMIT, bundleDigest: sha('build-bundle'), policyDigest },
    dependencies: [{ name: 'lib', revision: DEP_COMMIT }],
    artifacts: [{ name: 'app.tgz', digest: sha('artifact') }],
    scope: { description: 'synthetic scope: two supported checks', mandatory: ['sast', 'invariants', 'replay'] },
    graphSnapshot: { digest: sha('graph') },
    invariantVersions: [{ id: 'inv-tenant', version: '3' }],
    verificationReceipts: receipts,
    checks: {
      completed: [
        { id: 'sast', statement: 'static analysis ran', evidenceRefs: ['vrec:0001'] },
        { id: 'invariants', statement: 'tenant invariant held', evidenceRefs: ['vrec:0002'] },
      ],
      incomplete: [{ id: 'replay', statement: 'runtime replay', evidenceRefs: [], gaps: ['no confinement backend on this host'] }],
      unsupported: [], waived: [],
    },
    policy: { id: 'policy-v1', digest: policyDigest, blockingSeverity: 'high' },
    findings: { total: 4, blocking: 0 },
    residualRisks: [{ id: 'rr-1', statement: 'replay not executed', severity: 'medium' }],
    ...over,
  };
}

export const syntheticManifest = (over) => buildManifest(manifestFacts(over));

export function exportSynthetic(outDir, { manifest = syntheticManifest(), findings, replayManifests } = {}) {
  return exportBundle({
    outDir, manifest,
    findings: findings ?? [{ id: 'F1', severity: 'low', file: 'a.js', line: 3, vuln: 'x', cwe: 'CWE-79', description: 'synthetic finding', snippet: 'SECRET-SOURCE-TEXT', family: 'xss', parser: 'REGEX' }],
    provenance: { dependencies: [{ name: 'lib', revision: DEP_COMMIT }], note: 'synthetic provenance' },
    replayManifests: replayManifests ?? [{ id: 'rm-1', oracle: 'injection-execution', prerequisites: [{ code: 'node-runtime', statement: 'Node 24 is required' }] }],
    toolchain: { node: '24.0.0', engine: 'synthetic', platform: 'darwin' },
    receipts: RECEIPTS,
  });
}

export function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
}

// ---- scheduler fixtures (X-706 to X-708). SYNTHETIC repositories only.
export const DEPS = Object.fromEntries(['code', 'policy', 'graph', 'invariant', 'oracle', 'toolchain'].map((d) => [d, sha(`dep-${d}`)]));
export const EST = Object.freeze({ wallMs: 1000, spendUsd: 1, requests: 1, storageBytes: 10 });
export const estimateOf = () => EST;
export const ok = (unit) => ({ resultDigest: sha(`result-${unit.id}`), dependencies: DEPS });

/**
 * A plan with `spec[repo]` units per repository. Units of one repository differ by a required-input name, so a repository can hold
 * more units than there are task types. The plan object is assembled by hand (units merged from per-unit planPortfolio calls).
 */
export function manyUnitsPlan(spec) {
  const units = [];
  for (const [name, count] of Object.entries(spec)) {
    for (let i = 0; i < count; i++) {
      const p = planPortfolio({ repositories: [{ name, commit: COMMIT }], authorized: [name], taskTypes: ['sast-scan'], requiredInputs: { 'sast-scan': [`shard-${i}`] }, synthetic: true });
      units.push(...p.plan.units);
    }
  }
  units.sort((a, b) => (a.id < b.id ? -1 : 1));
  return { schema: 'agentic-security/portfolio-plan', schemaVersion: '1.0.0', synthetic: true, units, rejected: [], id: `pplan:test${units.length}x${Object.keys(spec).join('-')}` };
}

export const BIG_BUDGETS = (over = {}) => ({ portfolio: { concurrency: 1, wallMs: 1e9, spendUsd: 1e9, requests: 1e9, storageBytes: 1e12, ...over } });
