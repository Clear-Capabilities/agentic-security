// Protected wrapper for the "release" suite (REL-001 to REL-003 (REL-003 adds its own final suite later)).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'release',
  scope: 'release-closure',
  expectHelper: 'aa1aa071ce0cf7247979785ba2556e5a024963e211ad0bf5300d535a4641e10b',
});
