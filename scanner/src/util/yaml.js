// Thin wrapper over js-yaml.
//
// js-yaml 5 throws on empty input ("expected a document, but the input is
// empty") where 4.x returned undefined. Every YAML file this scanner reads is
// user-authored config — .agentic-security/rules.yml, suppressions.yml,
// profiles, policies — and an empty or fully commented-out config is a normal,
// intentional state, not an error. Without this shim a blank rules.yml prints a
// spurious parse error on every scan.
//
// Import this instead of js-yaml directly anywhere config is read.
import * as _yaml from 'js-yaml';

/** Parse YAML, returning undefined for blank/comment-only input (4.x behaviour). */
export function load(text, opts) {
  if (typeof text !== 'string') return undefined;
  // A document that is only whitespace and/or comments has no content. js-yaml
  // 4 returned undefined here; preserve that rather than surfacing a throw.
  const stripped = text.replace(/^\s*#.*$/gm, '').trim();
  if (stripped === '') return undefined;
  return _yaml.load(text, opts);
}

export const dump = _yaml.dump;
export const CORE_SCHEMA = _yaml.CORE_SCHEMA;
