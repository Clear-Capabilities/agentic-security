// Protected wrapper for the "release" suite (REL-001 to REL-003 (REL-003 adds its own final suite later)).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'release',
  scope: 'release-closure',
  expectHelper: '437c578cf5938c881dd8a9d375a782ef84856e70b0392eaf83b5a477d1a13b97',
});
