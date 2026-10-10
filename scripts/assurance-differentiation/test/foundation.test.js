// Protected wrapper for the "foundation" suite (CORE-001 to CORE-004: baseline inventory, versioned contracts and identities, the trusted verification boundary, issuer and trust basis, configuration).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'foundation',
  files: ["test/posture/assurance-config.test.js","test/posture/assurance-contracts.test.js","test/posture/assurance-baseline.test.js","test/evidence-issuer.test.js","test/trust-boundary.test.js"],
  expectHelper: 'aa1aa071ce0cf7247979785ba2556e5a024963e211ad0bf5300d535a4641e10b',
});
