// Protected wrapper for the "invariants" suite (X-401 to X-408).
// It runs the real scoped test files and re-emits each result under its own name; see relay.mjs.
// The helper digest below freezes what "pass" means for this wrapper.
import { relaySuite } from './relay.mjs';

await relaySuite({
  suite: 'invariants',
  scope: 'invariants',
  expectHelper: 'aa1aa071ce0cf7247979785ba2556e5a024963e211ad0bf5300d535a4641e10b',
});
