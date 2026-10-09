// The deterministic inputs behind the previous-schema compatibility fixtures (X-206.AC03).
//
// The `*.v0.json` files next to this one were CAPTURED by running these inputs through the sources of commit 0a03121b, the
// last commit before the interface-equivalence work, so they record what each interface emitted BEFORE it carried the shared
// verification projection. The compatibility test feeds the same inputs to the current code and requires every previous
// field to still be present with the same value: changes are additive. To recapture, extract that commit's `scanner/src`,
// run `capture.mjs` against it (see docs/guides/verification-schema-migration.md) and review the diff.
export const COMMIT = 'a1'.repeat(20);

export const FINDING = Object.freeze({
  id: 'F-compat-1', severity: 'high', file: 'src/orders.js', line: 7, vuln: 'Command injection', cwe: 'CWE-78',
  family: 'injection', parser: 'SAST', stableId: 'stable-compat-1',
  description: 'user input reaches a shell', remediation: 'pass arguments as an array',
});

export const META = Object.freeze({ scanId: 'scan-compat', startedAt: '2026-10-09T00:00:00.000Z', durationMs: 1 });

export function scanInput() {
  return { findings: [{ ...FINDING }], filesScanned: 1, linesScanned: 10 };
}

/** Stages for runAutopilot: a proved finding with a patch that re-verifies under the older runner. */
export function autopilotStages() {
  return {
    scan: async () => ({ findings: [{ stableId: 'stable-compat-1', file: 'src/orders.js', line: 7, vuln: 'Command injection', severity: 'high', family: 'injection', parser: 'SAST' }] }),
    prove: async () => ({ proofTier: 'execution-proven', proofEvidence: { ran: true } }),
    validate: async () => ({ verdict: 'upheld' }),
    synthesizeFix: async () => ({ patch: { 'src/orders.js': 'patched' } }),
    verifyFix: async () => ({ ok: true, pocStillFires: false, testsPass: true }),
  };
}
