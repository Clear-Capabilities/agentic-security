// Protected wrapper for the "foundation" suite (CORE-001 to CORE-004: baseline inventory, versioned contracts and identities, the trusted verification boundary, issuer and trust basis, configuration).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'foundation',
  files: ["test/posture/assurance-config.test.js","test/posture/assurance-contracts.test.js","test/posture/assurance-baseline.test.js","test/evidence-issuer.test.js","test/trust-boundary.test.js"],
  expectHelper: '437c578cf5938c881dd8a9d375a782ef84856e70b0392eaf83b5a477d1a13b97',
});
