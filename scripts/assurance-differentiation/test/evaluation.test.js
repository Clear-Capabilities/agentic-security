// Protected wrapper for the "evaluation" suite (QA-001 to QA-008).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'evaluation',
  scope: 'evaluation',
  expectHelper: '437c578cf5938c881dd8a9d375a782ef84856e70b0392eaf83b5a477d1a13b97',
});
