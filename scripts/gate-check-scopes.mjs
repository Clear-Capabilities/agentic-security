// Per-check INPUT SCOPES for the pre-push gate's verdict cache.
//
// A cached PASS may be reused only when a digest of everything the check can
// read is unchanged. This file is where "everything the check can read" is
// written down, one entry per check, as repo-relative path prefixes (a prefix
// ending in "/" is a directory, anything else is one exact file).
//
// THE RULE FOR EDITING THIS FILE: a scope that is too wide costs a re-run; a
// scope that is too narrow lets a stale PASS stand over a change the check
// would have caught. So when unsure, widen. `all: true` (the whole tree) is the
// default for any check not listed, and for the two big suites.
//
// The scopes were derived from `node scripts/gate-trace-reads.mjs <id>`, which
// runs the real check under a read tracer, and are re-checked by
// `node scripts/gate-trace-reads.mjs <id> --verify` (exit 1 when the check read
// anything the scope does not cover). Re-run it whenever a bench changes what
// it loads. Directory-level prefixes rather than file lists are deliberate: a
// new fixture dropped into a directory the bench already walks is then covered.
import * as path from 'node:path';

/** Read by every gated npm check: the engine, its dependency pins, the bundle, and the gate's own code. */
export const COMMON = [
  // All of scanner/ except its test tree (see COMMON_EXCLUDE): the checks run with cwd=scanner/, and the traced runs
  // probe files there that do not exist (a config, a manifest), so an ADDED file must invalidate too.
  'scanner/',
  'scripts/pre-push-gate.mjs',
  'scripts/gate-verdict-cache.mjs',
  'scripts/gate-check-scopes.mjs',
  'scripts/gate-run-checks.mjs',
];

/** Subtrees of COMMON that a check does not read unless its own `include` names a path under them. */
export const COMMON_EXCLUDE = ['scanner/test/'];

/**
 * `writesRepo: false`: the check writes nothing inside the repository (verified by a traced run); only such checks may be
 * given a `parallelGroup`. Absent means unknown, which is never treated as safe to parallelise.
 * `scoped: false`: no per-check key is offered (see the entries). `cleanState`: roots whose gitignored scan-state directories the
 * gate removes before keying and running; the traced run may read or write scan state only under them.
 * `usesHistory`: the check runs git against THIS repository (commit sha is then
 * part of the key). `all`: the check may read any file.
 */
const SCOPES = {
  // `scoped: false` -> these keep only the whole-tree cache (gate-verdict-cache.mjs). Their scan state and history reads were not
  // traced (the run is far too long under the tracer), so a narrower key cannot be backed by evidence and none is offered.
  'ci-parity': { scoped: false, all: true, usesHistory: true },
  'test-suite': { scoped: false, all: true, usesHistory: true },
  'self-scan-gate': { scoped: false, all: true, usesHistory: true },
  'corpus-gate': { include: ['bench/cve-replay/', 'bench/_lib/', 'bench/family-producers/', 'scanner/test/helpers/'], usesHistory: true, cleanState: ['bench/cve-replay/'] },
  'mutation-gate': { include: ['bench/mutation/', 'bench/_lib/', 'bench/family-producers/'], usesHistory: false, writesRepo: false },
  'protection-verdict-gate': { include: ['bench/protection-verdict/', 'bench/_lib/'], usesHistory: false, writesRepo: false },
  'provenance-accuracy-gate': { include: ['bench/provenance-accuracy/', 'bench/_lib/', 'bench/family-producers/', 'scanner/test/helpers/'], usesHistory: false, writesRepo: false },
  'layer-recall-gate': { include: ['bench/layer-recall/', 'bench/cve-replay/', 'bench/_lib/', 'bench/family-producers/', 'docs/METRICS.md'], usesHistory: true, cleanState: ['bench/cve-replay/'] },
  'language-support-gate': { include: ['bench/language-support/', 'bench/_lib/', 'scanner/test/language/', 'docs/language-support.json', 'docs/language-support.md', 'docs/language-toolchain.json'], usesHistory: false, writesRepo: false },
};

export function scopeFor(checkId) {
  const s = SCOPES[checkId];
  // An unlisted check has no traced scope: whole tree, history, and no scoped key at all.
  if (!s) return { scoped: false, all: true, usesHistory: true, writesRepo: null, cleanState: [], include: [...COMMON] };
  return {
    scoped: s.scoped !== false, all: Boolean(s.all), usesHistory: Boolean(s.usesHistory),
    writesRepo: s.writesRepo === false ? false : null, cleanState: s.cleanState || [], include: [...COMMON, ...(s.include || [])],
  };
}

// A directory include also matches the directory itself (a bench that lists or stats `bench/x` reads that path, not a file under it).
const matches = (i, p) => (i.endsWith('/') ? p.startsWith(i) || `${p}/` === i : p === i);

export function pathInScope(scope, rel) {
  if (scope.all) return true;
  const p = rel.split(path.sep).join('/');
  // Files at the repository root: tools walk up from the working directory probing for config files, so any root-level
  // non-prose file is an input. Prose (*.md, LICENSE, NOTICE) was not read by any traced check.
  if (!p.includes('/') && !/\.md$/.test(p) && p !== 'LICENSE' && p !== 'NOTICE') return true;
  const hit = scope.include.filter((i) => matches(i, p));
  if (hit.length === 0) return false;
  const excluded = COMMON_EXCLUDE.some((e) => p.startsWith(e));
  // An excluded subtree is in scope only through an include that is itself inside it.
  return !excluded || hit.some((i) => COMMON_EXCLUDE.some((e) => i.startsWith(e)));
}
