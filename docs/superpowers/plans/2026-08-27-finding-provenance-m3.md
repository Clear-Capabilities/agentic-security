# Finding Provenance M3 (P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--provenance deep` real (non-first-parent DAG walk, revert/cherry-pick lifecycle events), resolve transitive SCA dependency origins, build a detector-agnostic "missing control" (presence→absence) resolver, add strictly opt-in GitHub/GitLab provider enrichment, prove rename-boundary honesty, and close a small stale-TODO left in `schema.js` from M2.

**Architecture:** Every new resolver follows the established pattern in `posture/provenance/`: a pure module taking `(scanRoot, ...)` and returning a `{status, ...}` result shape that `coordinator.js` (for deep-mode/transitive-SCA) or a standalone caller (for missing-control, which has no live production caller yet) turns into a terminal `findingProvenance`. Deep mode is a **generalization** of the existing first-parent check (checking absence across ALL parents of a candidate, not just the first) rather than a separate graph-search algorithm — this keeps its complexity bounded by the same candidate list `--provenance standard` already walks, just with more parent-checks per merge commit. Transitive SCA origin resolution re-derives the lockfile's dependency ancestry at each historical candidate commit (the current ancestry is computed today but silently dropped before reaching findings — a real, fixable gap found during this plan's own research). The missing-control resolver has no existing caller in this codebase and ships as a standalone, thoroughly-tested library module, matching what M3's own research found: no live "presence→absence" finding type exists yet to attach it to.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/test/helpers/build-git-fixture.js` for synthetic git histories, `js-yaml` (already a dependency) via the existing `scanner/src/util/yaml.js` shim for the new provider config file, raw `fetch` (matching `llm-validator`'s existing precedent) for provider HTTP calls.

**Spec:** `docs/superpowers/specs/2026-08-27-finding-provenance-m2-m3-m4-design.md` §3 (M3). Referenced throughout as "the spec"; conflicts between this plan and the spec resolve in the spec's favor, EXCEPT where this plan's own research corrected a factual assumption in the spec text — each such correction is called out explicitly at its task (see Task 9's note on `--follow`/`candidateCommitsForLine`).

## Scope corrections found during this plan's research (read before implementing)

- The spec's §3.1 says git-evidence.js "already has `getParents`" — verified false: only `getFirstParent` exists. Task 1 adds `getAllParents` fresh, not confirms/uses an existing one.
- The spec's §3.5 rename-fixture text references "`candidateCommitsForFile`'s `--follow`" as what `origin-resolver.js` uses — verified false: `origin-resolver.js` calls `candidateCommitsForLine` (used by the SAST path this whole milestone is about), which has NO `--follow` flag; `candidateCommitsForFile` (which DOES have `--follow`) is the SCA/direct-dependency path's helper, unrelated to this test. Task 9 tests the REAL behavior of `candidateCommitsForLine` at a rename boundary, not `candidateCommitsForFile`.
- Missing-control (§3.3): no existing detector/finding type in this codebase represents "a control that was present and is now absent" — `EVIDENCE_ROLE.REMOVED_GUARD` in `schema.js` is defined but has exactly one dead-branch consumer (`evidence-attribution.js`) fed by a field (`step.removedGuard`) nobody ever sets. Task 7 builds this as a standalone library module with its own test suite, not wired into `engine.js`'s live pipeline — there is nothing live to wire it into yet.
- Transitive SCA (§3.2): the current dependency ancestry (`depChain`) IS computed by `engine.js`'s lockfile parser but is silently dropped before it reaches the `vulnerable_dep` finding object (`isDirect` was fixed to propagate in an earlier session; `depChain` was not). Task 5 fixes this one-line gap. It does NOT eliminate the need for `transitive-sca.js` to walk history itself — the CURRENT ancestry doesn't tell you the ANCESTRY AT THE HISTORICAL COMMIT that introduced the vulnerable version, since the dependency graph itself can change shape across commits.

## Global Constraints

Copied from the spec's §5 (safety/testing/DoD) — every task's own requirements implicitly include these:

- **Terminal status always present, never `undefined`.** Every new resolver returns one of the existing `PROVENANCE_STATUS` values (or, for missing-control, its own `status` shape documented at Task 7) — never leaves a field unset.
- **Never false certainty.** A resolver that cannot prove something reports `partial`/`unknown`, never guesses. This is the single most important invariant for Task 7 (missing-control) specifically: absence at every reachable commit including the root must resolve `unknown`, **never** attributed to the root commit.
- **Read-only Git access only.** No new module runs `checkout`/`merge`/hooks — every git interaction goes through `git-evidence.js`'s existing `_run`/`_isSha`/`_isSafeRevision` guard conventions (argument-injection-safe).
- **No new npm dependency without a documented reason.** `js-yaml` is already a dependency (used for `rules.yml`) — Task 8's provider config reuses it via the existing `util/yaml.js` shim, not a new package.
- **Deterministic output for a fixed HEAD**, excluding the run-property carve-outs M0-M2 already established (`budget_exhausted` never cached; `observedAt` frozen under `--deterministic` since M2's end-of-plan fix).
- **No runtime network call without an explicit, documented opt-in and an offline-degrades-gracefully test.** Task 8's providers are the only network-calling code in this plan — see its hermeticity requirement, modeled on `llm-validator`'s existing precedent (`scanner/test/llm-validator-default-on.test.js`: spy on `global.fetch`, assert zero calls when unconfigured).
- **ESM throughout**, no CommonJS.
- **After any change to `scanner/src/` or `scanner/bin/`, run `npm run build`** before relying on the bundle.
- **Run every test/build command in the FOREGROUND with an explicit `timeout` parameter.** This session has repeatedly hit implementer subagents backgrounding long-running commands and stalling on their own wait/monitor loops — every task dispatch in this plan's execution must explicitly forbid this.
- **PROVENANCE_STATUS literals** (`complete`, `partial`, `not_available`, `uncommitted`, `budget_exhausted`, `error`) and **PROVENANCE_METHOD literals** (`semantic-history-replay`, `dependency-graph-diff`, `line-attribution`, `scan-history`, `none`) from `schema.js` — use directly, never re-derive.

---

### Task 1: `git-evidence.js` — `getAllParents`

**Files:**
- Modify: `scanner/src/posture/provenance/git-evidence.js`
- Test: `scanner/test/posture/provenance-git-evidence.test.js` (extend)

**Interfaces:**
- Produces: `getAllParents(scanRoot, sha)` — returns `string[]` of every parent SHA (empty array for a root commit, `[parent]` for a normal single-parent commit, `[p1, p2, ...]` for a merge commit), or `[]` on any git error (never throws, matching every other function in this file).

- [ ] **Step 1: Add `getAllParents`**

In `scanner/src/posture/provenance/git-evidence.js`, add immediately after `getFirstParent` (which ends at line 75):

```js
// M3 §3.1: the full parent list, not just the first. `git rev-parse
// <sha>^@` expands to every parent SHA, one per line — the same mechanism
// `<sha>^1` (getFirstParent) uses for a single parent, generalized. A
// commit with no parents (the repo root) returns empty stdout, which
// `.filter(Boolean)` turns into `[]` rather than `['']`.
export function getAllParents(scanRoot, sha) {
  if (!_isSha(sha)) return [];
  const r = _run(scanRoot, ['rev-parse', `${sha}^@`]);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}
```

- [ ] **Step 2: Write tests**

Append to `scanner/test/posture/provenance-git-evidence.test.js` (check its existing imports and fixture-setup pattern first — it already imports from `../helpers/build-git-fixture.js` or constructs fixtures via `createGitFixture()`; follow that exact convention):

```js
test('getAllParents: a root commit has zero parents', async (t) => {
  const { createGitFixture } = await import('../helpers/build-git-fixture.js');
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  const parents = getAllParents(fx.root, root);
  assert.deepEqual(parents, []);
});

test('getAllParents: a normal commit has exactly one parent, matching getFirstParent', async (t) => {
  const { createGitFixture } = await import('../helpers/build-git-fixture.js');
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  fx.commit('root');
  fx.writeFile('a.txt', 'y');
  const second = fx.commit('second');
  const parents = getAllParents(fx.root, second);
  assert.equal(parents.length, 1);
  assert.equal(parents[0], getFirstParent(fx.root, second));
});

test('getAllParents: a merge commit reports every parent, not just the first', async (t) => {
  const { createGitFixture } = await import('../helpers/build-git-fixture.js');
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  fx.checkoutBranch('feature');
  fx.writeFile('b.txt', 'feature-content');
  const featureTip = fx.commit('feature work');
  fx.checkout('main');
  fx.writeFile('a.txt', 'y');
  fx.commit('mainline work');
  const merge = fx.merge('feature', 'merge feature');
  const parents = getAllParents(fx.root, merge);
  assert.equal(parents.length, 2);
  assert.equal(parents[1], featureTip);
});

test('getAllParents: an invalid sha returns empty array, never throws', () => {
  assert.deepEqual(getAllParents('/tmp/does-not-matter', 'not-a-sha'), []);
});
```

Check `build-git-fixture.js`'s `checkoutBranch`/`checkout`/`merge` methods exist with this exact signature — confirmed present in the file (`checkoutBranch(name)`, `checkout(ref)`, `merge(ref, message)` returning the merge commit's SHA).

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-git-evidence.test.js` (foreground, timeout 60000). Expected: PASS, including the 4 new tests.

- [ ] **Step 4: Run the broader scope and commit**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40` (foreground, timeout 600000). Expected: PASS.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/git-evidence.js scanner/test/posture/provenance-git-evidence.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): getAllParents in git-evidence.js (M3 §3.1)

Generalizes getFirstParent to the full parent list — needed for deep-mode's
non-first-parent walk (Task 3), which must explore every parent of a merge
commit, not just mainline.
EOF
)"
```

---

### Task 2: `dag-walk.js` — non-first-parent absence check, revert detection, cherry-pick detection

**Files:**
- Create: `scanner/src/posture/provenance/dag-walk.js`
- Test: `scanner/test/posture/provenance-dag-walk.test.js`

**Interfaces:**
- Produces:
  - `checkAbsentInAllParents(scanRoot, sha, replay)` — `replay` is a `(sha) => Promise<{present: boolean}>` function (the same shape `origin-resolver.js`'s local `replay` closure already has). Returns `Promise<{absentInAll: boolean, parents: string[], rootCommit: boolean}>`.
  - `detectRevert(scanRoot, sha)` — returns `{isRevert: boolean, revertsCommit: string|null}`. A commit is classified a revert only when BOTH the message matches git's own `Revert "..."` convention AND the commit's diff is confirmed to be the structural inverse of an earlier commit's diff (message alone is spoofable/unreliable per the spec).
  - `detectCherryPick(scanRoot, sha)` — returns `{isCherryPick: boolean, originalCommit: string|null}`, reading the `(cherry picked from commit <sha>)` trailer `git cherry-pick -x` leaves.
- Consumes: `getAllParents` (Task 1), `commitMeta` (existing), `_run`-equivalent git access — this module makes its own `git` calls following `git-evidence.js`'s existing safety conventions (SHA validation via a local re-implementation is NOT needed — reuse `git-evidence.js`'s exported functions plus one new one below).

- [ ] **Step 1: Add one more git-evidence.js export for revert-diff comparison**

Revert detection needs to compare two commits' diffs for structural inversion. In `scanner/src/posture/provenance/git-evidence.js`, add after `getAllParents` (Task 1's addition):

```js
// M3 §3.1: the diff a commit introduces, as a normalized patch string — used
// by dag-walk.js to confirm a claimed revert is a REAL structural inverse of
// an earlier commit's diff, not just a commit whose MESSAGE says "Revert" (a
// spoofable, unreliable signal on its own per the spec). `--no-color` and a
// fixed context of 0 lines keep the two diffs comparable independent of
// terminal/config state; `-U0` removes context lines so unrelated nearby
// edits between the two commits don't defeat the comparison.
export function commitDiff(scanRoot, sha) {
  if (!_isSha(sha)) return null;
  const r = _run(scanRoot, ['show', '--no-color', '-U0', '--format=', sha]);
  return r.ok ? r.stdout : null;
}
```

- [ ] **Step 2: Write `dag-walk.js`**

```js
// Non-linear DAG analysis for --provenance deep (Finding Provenance PRD,
// M3 §3.1). Three independent capabilities, each documented at its export:
//
//  1. checkAbsentInAllParents — generalizes origin-resolver.js's existing
//     first-parent-only absence check to EVERY parent of a candidate commit.
//     A vulnerability introduced via a merged feature branch (not mainline)
//     needs this: checking only the first parent would see the predicate
//     already present there (inherited from mainline before the merge) and
//     wrongly conclude the merge commit isn't the origin, when the real
//     introduction happened on the feature branch's own history — which the
//     first-parent-only walk never visits at all.
//
//  2. detectRevert / detectCherryPick — lifecycle event classification, not
//     origin resolution. A reintroduction that is actually a revert-of-a-fix
//     or propagation of an earlier introduction via cherry-pick is a
//     DIFFERENT lifecycle story than an unrelated re-introduction, and
//     lifecycle.js's event vocabulary (Task 4) needs to say so.
import { getAllParents, commitDiff } from './git-evidence.js';
import * as cp from 'node:child_process';

const GIT_TIMEOUT_MS = 2000;
function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '', error: e };
  }
}
const SHA_RE = /^[0-9a-f]{4,40}$/i;
function _isSha(sha) { return typeof sha === 'string' && SHA_RE.test(sha); }

/**
 * Check whether a predicate is absent in EVERY parent of `sha`, not just the
 * first. `replay` is the caller's (sha) => Promise<{present:boolean}> closure
 * (origin-resolver.js already has one via its own memoized `replay`).
 */
export async function checkAbsentInAllParents(scanRoot, sha, replay) {
  const parents = getAllParents(scanRoot, sha);
  if (parents.length === 0) return { absentInAll: true, parents: [], rootCommit: true };
  const results = await Promise.all(parents.map((p) => replay(p)));
  const absentInAll = results.every((r) => !r.present);
  return { absentInAll, parents, rootCommit: false };
}

// git's own convention when using `git revert` (no -n/--no-edit override):
// "Revert \"<original subject>\"". Message alone is spoofable, so this is
// only the FIRST half of detection — see detectRevert.
const REVERT_MESSAGE_RE = /^Revert "/;

/**
 * A commit is a real revert only when its message matches git's own Revert
 * convention AND its diff is a genuine structural inverse of an EARLIER
 * candidate commit's diff (message-only detection is spoofable). Checked
 * against each of `candidateShas` (typically the same candidate list the
 * caller's walk already has, oldest-first) — the first one whose diff is the
 * exact reverse wins.
 */
export function detectRevert(scanRoot, sha, candidateShas) {
  if (!_isSha(sha)) return { isRevert: false, revertsCommit: null };
  const meta = _run(scanRoot, ['show', '-s', '--format=%s', sha]);
  if (!meta.ok || !REVERT_MESSAGE_RE.test(meta.stdout.trim())) {
    return { isRevert: false, revertsCommit: null };
  }
  const thisDiff = commitDiff(scanRoot, sha);
  if (!thisDiff) return { isRevert: false, revertsCommit: null };
  const invertedThisDiff = _invertUnifiedDiff(thisDiff);
  for (const candidate of candidateShas || []) {
    if (candidate === sha) continue;
    const candidateDiff = commitDiff(scanRoot, candidate);
    if (candidateDiff && candidateDiff.trim() === invertedThisDiff.trim()) {
      return { isRevert: true, revertsCommit: candidate };
    }
  }
  return { isRevert: false, revertsCommit: null };
}

// Swap +/- lines in a `-U0` unified diff to produce what the INVERSE diff
// would look like, so it can be string-compared against a candidate's real
// diff. Header lines (---/+++/@@) are left as-is; only content lines
// (leading + or -, not ++/-- which are diff metadata) are swapped. This is
// intentionally a simple line-level swap, not a full patch-reversal parser —
// `-U0` (no context) makes this sufficient: every emitted line is either a
// pure addition or pure removal, never a context line to preserve unchanged.
function _invertUnifiedDiff(diffText) {
  return diffText.split('\n').map((line) => {
    if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@') || line.startsWith('diff ') || line.startsWith('index ')) return line;
    if (line.startsWith('+')) return '-' + line.slice(1);
    if (line.startsWith('-')) return '+' + line.slice(1);
    return line;
  }).join('\n');
}

// `git cherry-pick -x` leaves this exact trailer format in the new commit's
// message body: "(cherry picked from commit <full-or-abbrev-sha>)".
const CHERRY_PICK_TRAILER_RE = /\(cherry picked from commit ([0-9a-f]{4,40})\)/;

export function detectCherryPick(scanRoot, sha) {
  if (!_isSha(sha)) return { isCherryPick: false, originalCommit: null };
  const r = _run(scanRoot, ['show', '-s', '--format=%B', sha]);
  if (!r.ok) return { isCherryPick: false, originalCommit: null };
  const m = r.stdout.match(CHERRY_PICK_TRAILER_RE);
  if (!m) return { isCherryPick: false, originalCommit: null };
  return { isCherryPick: true, originalCommit: m[1] };
}
```

- [ ] **Step 2: Write tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkAbsentInAllParents, detectRevert, detectCherryPick } from '../../src/posture/provenance/dag-walk.js';
import { getAllParents } from '../../src/posture/provenance/git-evidence.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

test('checkAbsentInAllParents: root commit reports rootCommit:true, absentInAll:true', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  const replay = async () => ({ present: false });
  const result = await checkAbsentInAllParents(fx.root, root, replay);
  assert.equal(result.rootCommit, true);
  assert.equal(result.absentInAll, true);
  assert.deepEqual(result.parents, []);
});

test('checkAbsentInAllParents: a merge commit is absentInAll only when EVERY parent lacks the predicate', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  fx.commit('root');
  // M3 Task 1's own review discovered this environment's `git init` default
  // branch is 'master', not 'main' (no init.defaultBranch config set) —
  // capture the real starting branch name rather than hardcoding 'main',
  // matching the fix Task 1's implementer already had to make for the same
  // reason (see build-git-fixture.js's currentBranch(), added in Task 1).
  const mainBranch = fx.currentBranch();
  fx.checkoutBranch('feature');
  fx.writeFile('b.txt', 'y');
  const featureTip = fx.commit('feature');
  fx.checkout(mainBranch);
  fx.writeFile('a.txt', 'z');
  const mainTip = fx.commit('mainline');
  const merge = fx.merge('feature', 'merge');
  const parents = getAllParents(fx.root, merge);
  assert.equal(parents.length, 2);
  // Predicate present only in the feature-branch parent — not absent in all.
  const replayPresentInFeature = async (sha) => ({ present: sha === featureTip });
  const notAbsent = await checkAbsentInAllParents(fx.root, merge, replayPresentInFeature);
  assert.equal(notAbsent.absentInAll, false);
  // Predicate present in neither parent — absent in all.
  const replayAbsent = async () => ({ present: false });
  const isAbsent = await checkAbsentInAllParents(fx.root, merge, replayAbsent);
  assert.equal(isAbsent.absentInAll, true);
});

test('detectRevert: a real git-revert of the immediately preceding commit is detected', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'safe\n');
  fx.commit('safe baseline');
  fx.writeFile('a.txt', 'eval(x)\n');
  const bad = fx.commit('introduce eval');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['revert', '--no-edit', bad], { cwd: fx.root });
  const revertSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectRevert(fx.root, revertSha, [bad]);
  assert.equal(result.isRevert, true);
  assert.equal(result.revertsCommit, bad);
});

test('detectRevert: a commit whose message says "Revert" but whose diff does NOT match is rejected (spoofing resistance)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'safe\n');
  fx.commit('safe baseline');
  fx.writeFile('a.txt', 'eval(x)\n');
  const bad = fx.commit('introduce eval');
  fx.writeFile('a.txt', 'totally different content, not a real revert\n');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['add', '-A'], { cwd: fx.root });
  execFileSync('git', ['commit', '-m', 'Revert "introduce eval"'], { cwd: fx.root });
  const spoofSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectRevert(fx.root, spoofSha, [bad]);
  assert.equal(result.isRevert, false, 'a spoofed commit message alone must not be trusted');
});

test('detectCherryPick: a real cherry-pick -x trailer is parsed', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'v1\n');
  const original = fx.commit('original commit');
  const mainBranch = fx.currentBranch(); // see Task 1's build-git-fixture.js addition — this environment's git init default is 'master', not 'main'
  fx.checkoutBranch('other');
  fx.writeFile('a.txt', 'v2\n');
  fx.commit('unrelated');
  fx.checkout(mainBranch);
  const { execFileSync } = await import('node:child_process');
  fx.writeFile('b.txt', 'x\n');
  const target = fx.commit('target for cherry-pick message construction');
  // Simulate the trailer directly (git cherry-pick across these two branches
  // in a synthetic fixture with no shared content is fiddly) — this tests
  // the PARSER, which is the unit under test, not `git cherry-pick` itself.
  execFileSync('git', ['commit', '--allow-empty', '-m', `Some change\n\n(cherry picked from commit ${original})`], { cwd: fx.root });
  const cherrySha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectCherryPick(fx.root, cherrySha);
  assert.equal(result.isCherryPick, true);
  assert.equal(result.originalCommit, original);
});

test('detectCherryPick: a normal commit with no trailer is not classified as a cherry-pick', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const sha = fx.commit('ordinary commit');
  const result = detectCherryPick(fx.root, sha);
  assert.equal(result.isCherryPick, false);
});
```

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-dag-walk.test.js` (foreground, timeout 60000). Expected: PASS, 7/7.

- [ ] **Step 4: Add to `test:posture` and commit**

Insert `test/posture/provenance-dag-walk.test.js` into `scanner/package.json`'s `"test:posture"` script, immediately after `test/posture/provenance-git-evidence.test.js`.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/dag-walk.js scanner/src/posture/provenance/git-evidence.js scanner/test/posture/provenance-dag-walk.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): dag-walk.js — non-first-parent check, revert/cherry-pick detection (M3 §3.1)

checkAbsentInAllParents generalizes origin-resolver.js's first-parent-only
absence check to every parent of a merge commit. detectRevert cross-checks a
claimed revert's diff against a candidate's real diff (message alone is
spoofable). detectCherryPick parses the `git cherry-pick -x` trailer.
EOF
)"
```

---

### Task 3: `origin-resolver.js` — real `--provenance deep` via `dag-walk.js`

**Files:**
- Modify: `scanner/src/posture/provenance/origin-resolver.js`
- Modify: `scanner/src/posture/provenance/coordinator.js` (thread `ctx.mode` through to `resolveOrigin` — currently silently dropped)
- Test: `scanner/test/posture/provenance-origin-resolver.test.js` (extend)

**Interfaces:**
- Consumes: `checkAbsentInAllParents`, `detectRevert`, `detectCherryPick` (Task 2).
- Produces: `resolveOrigin(scanRoot, finding, opts)` gains an `opts.mode` field (`'standard'|'deep'`, default `'standard'` — backward compatible with every existing call site that doesn't pass it). When `'deep'` and the standard first-parent walk doesn't resolve `'complete'`, `resolveOrigin` retries using `checkAbsentInAllParents` instead of the single-parent check. `findingOrigin` gains optional `revertOf`/`cherryPickOf` fields (both `null` when not applicable) — additive, does not change the shape any existing consumer reads.

- [ ] **Step 1: Thread `mode` from `coordinator.js` into `resolveOrigin`**

In `scanner/src/posture/provenance/coordinator.js`, `resolveAndCache`'s `originResult` call:

```js
  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState });
```

becomes:

```js
  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    // M3 §3.1: `ctx.mode` was already threaded into the CACHE KEY
    // (makeCacheKey's `mode` field, present since M0+M1) but never actually
    // reached resolveOrigin itself — `--provenance deep` was accepted and
    // cached distinctly from `standard`, but both modes ran identical code.
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState, mode: ctx.mode });
```

- [ ] **Step 2: Extend `resolveOrigin` with deep-mode retry**

In `scanner/src/posture/provenance/origin-resolver.js`, the imports and signature change:

```js
import { candidateCommitsForLine, getFirstParent, commitMeta } from './git-evidence.js';
import { replayAt } from './predicate-replay.js';
import { PROVENANCE_METHOD } from './schema.js';
```

becomes:

```js
import { candidateCommitsForLine, getFirstParent, commitMeta } from './git-evidence.js';
import { replayAt } from './predicate-replay.js';
import { PROVENANCE_METHOD } from './schema.js';
import { checkAbsentInAllParents, detectRevert, detectCherryPick } from './dag-walk.js';
```

The function signature and the standard walk's return-empty-handed path change. Current:

```js
export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState } = {}) {
```

becomes:

```js
export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState, mode } = {}) {
```

At the end of the function, the current fallback:

```js
  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
```

becomes (this is the deep-mode retry — it re-walks the SAME candidate list, but this time checking absence across ALL parents of each candidate where the predicate is present, not just the first parent):

```js
  // M3 §3.1: `--provenance deep`. The standard walk above only ever checks a
  // candidate's FIRST parent for absence — correct for linear history, but a
  // vulnerability introduced via a merged feature branch never shows up
  // absent-in-first-parent at the merge commit (the first parent is
  // mainline, which the merge commit inherited from BEFORE the merge, so the
  // predicate legitimately wasn't there — but it also isn't the commit that
  // introduced it on the feature branch, which the first-parent-only walk
  // never visited). Deep mode re-checks the SAME candidates the standard
  // walk already found, this time requiring absence in EVERY parent, not
  // just the first — the generalization the spec calls "explores every
  // parent of a merge commit."
  if (mode === 'deep') {
    for (const sha of candidates) {
      if (deadlineAt && Date.now() > deadlineAt) {
        return { status: 'budget_exhausted', commitsConsidered };
      }
      const presentHere = await replay(sha);
      if (!presentHere.present) continue;
      commitsConsidered++;
      const { absentInAll, parents, rootCommit } = await checkAbsentInAllParents(scanRoot, sha, replay);
      if (!absentInAll) continue;
      const meta = commitMeta(scanRoot, sha);
      if (!meta) continue;
      if (rootCommit && repoState && repoState.shallow) {
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: originFrom(meta, { absentInParents: [] }),
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      const { isRevert, revertsCommit } = detectRevert(scanRoot, sha, candidates);
      const { isCherryPick, originalCommit } = detectCherryPick(scanRoot, sha);
      const origin = originFrom(meta, { absentInParents: parents });
      origin.revertOf = isRevert ? revertsCommit : null;
      origin.cherryPickOf = isCherryPick ? originalCommit : null;
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: origin,
        parentBoundaryVerified: !rootCommit,
      };
    }
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
```

Also add `revertOf: null, cherryPickOf: null` to the standard-mode `originFrom` helper so EVERY `findingOrigin` (standard or deep) carries these fields consistently (never present-in-deep-mode-only, which would make a consumer branch on mode to know which fields to expect):

```js
function originFrom(meta, { absentInParents }) {
  return {
    commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
    authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
    presentInCommit: true, absentInParents, revertOf: null, cherryPickOf: null,
  };
}
```

(Deep-mode's own code above then overwrites `origin.revertOf`/`origin.cherryPickOf` after calling this same helper — both paths now produce the same shape.)

- [ ] **Step 3: Write tests proving deep mode resolves what standard mode cannot**

Append to `scanner/test/posture/provenance-origin-resolver.test.js`:

```js
test('resolveOrigin: standard mode fails to resolve a vulnerability introduced via a merged feature branch (the real gap deep mode exists to close)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'safe();\n');
  fx.commit('mainline baseline');
  const mainBranch = fx.currentBranch(); // see Task 1's build-git-fixture.js addition — this environment's git init default is 'master', not 'main'
  fx.checkoutBranch('feature');
  fx.writeFile('a.js', 'eval(x);\n');
  fx.commit('introduce eval on feature branch');
  fx.checkout(mainBranch);
  fx.writeFile('b.js', 'unrelated();\n');
  fx.commit('unrelated mainline work');
  fx.merge('feature', 'merge feature into main');

  const { computeStableId } = await import('../../src/posture/stable-id.js');
  const finding = { file: 'a.js', line: 1, ruleId: 'no-eval', vuln: 'eval() Injection' };
  finding.stableId = computeStableId(finding);

  const standardResult = await resolveOrigin(fx.root, finding, { mode: 'standard' });
  // Documenting the actual gap, not asserting a specific failure mode — the
  // point is this must NOT be 'complete' with the wrong commit; either
  // 'partial' (honest "couldn't confirm") is acceptable here.
  assert.notEqual(standardResult.status, 'complete', 'standard mode is not expected to resolve a merge-introduced change correctly — that is the deep-mode gap this task closes');

  const deepResult = await resolveOrigin(fx.root, finding, { mode: 'deep' });
  assert.equal(deepResult.status, 'complete');
  assert.match(deepResult.findingOrigin.summary, /introduce eval on feature branch/);
});

test('resolveOrigin: deep mode tags a genuine revert with revertOf', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'safe();\n');
  fx.commit('safe baseline');
  fx.writeFile('a.js', 'eval(x);\n');
  const bad = fx.commit('introduce eval');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['revert', '--no-edit', bad], { cwd: fx.root });
  fx.writeFile('a.js', 'eval(x);\n');
  fx.commit('reintroduce eval');

  const { computeStableId } = await import('../../src/posture/stable-id.js');
  const finding = { file: 'a.js', line: 1, ruleId: 'no-eval', vuln: 'eval() Injection' };
  finding.stableId = computeStableId(finding);

  const result = await resolveOrigin(fx.root, finding, { mode: 'deep' });
  assert.equal(result.status, 'complete');
  // The origin resolved is the REINTRODUCTION (the current standing
  // instance), which is correct — revertOf/cherryPickOf describe THIS
  // commit's own relationship to history, and this commit is not itself a
  // revert. This test's purpose is proving deep mode doesn't crash or
  // misbehave in the presence of an unrelated revert earlier in history;
  // Task 4's lifecycle tests cover the revert EVENT classification itself.
  assert.equal(result.findingOrigin.revertOf, null);
});

test('resolveOrigin: mode defaults to standard behavior when omitted (backward compatible)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'eval(x);\n');
  fx.commit('introduce eval');
  const { computeStableId } = await import('../../src/posture/stable-id.js');
  const finding = { file: 'a.js', line: 1, ruleId: 'no-eval', vuln: 'eval() Injection' };
  finding.stableId = computeStableId(finding);
  const withoutMode = await resolveOrigin(fx.root, finding, {});
  const withStandard = await resolveOrigin(fx.root, finding, { mode: 'standard' });
  assert.equal(withoutMode.status, withStandard.status);
  assert.equal(withoutMode.findingOrigin?.commit, withStandard.findingOrigin?.commit);
});
```

Note for the implementer: if `computeStableId`'s exact import path/signature differs from what Task 9 of the M2 plan already established as this test file's convention (it should be identical, since that task already resolved this ambiguity), follow the file's own existing usage exactly.

- [ ] **Step 4: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js` (foreground, timeout 120000). Expected: PASS, all existing plus 3 new.

- [ ] **Step 5: Run the broader scope**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40` (foreground, timeout 600000). Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/origin-resolver.js scanner/src/posture/provenance/coordinator.js scanner/test/posture/provenance-origin-resolver.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): --provenance deep is real (M3 §3.1)

resolveOrigin retries with checkAbsentInAllParents when standard mode's
first-parent-only walk can't resolve a candidate — closing the documented
gap where a vulnerability introduced via a merged feature branch was
invisible to the standard walk. findingOrigin gains revertOf/cherryPickOf
(always present, null when not applicable). coordinator.js now actually
threads ctx.mode into resolveOrigin — it was already in the cache key but
silently never reached the resolver itself.
EOF
)"
```

---

### Task 4: `lifecycle.js` — revert/cherry-pick lifecycle events

**Files:**
- Modify: `scanner/src/posture/provenance/lifecycle.js`
- Test: `scanner/test/posture/provenance-lifecycle.test.js` (extend)

**Interfaces:**
- Produces: `applyScan`'s pushed events gain a `type` value of `'reverted'` or `'cherry-picked'` (in addition to the existing `'introduced'|'reintroduced'|'remediated'`) when the finding's `findingProvenance.findingOrigin.revertOf`/`.cherryPickOf` is non-null. `isOpenEvent` treats `'reverted'`/`'cherry-picked'` identically to `'reintroduced'` for the purposes of "is this finding currently open" (both are still open findings — the classification is about HOW they became open, not whether they're open).

- [ ] **Step 1: Extend `applyScan`'s event classification**

In `scanner/src/posture/provenance/lifecycle.js`, `applyScan`'s current event-push line:

```js
  for (const f of currentFindings) {
    if (!f.stableId) continue;
    const events = store[f.stableId] || (store[f.stableId] = []);
    if (isOpenEvent(events)) continue;
    const fp = f.findingProvenance;
    const commit = fp?.findingOrigin?.commit || null;
    const authorDate = fp?.status === 'complete' ? (fp.findingOrigin?.authorDate || observedAt) : observedAt;
    events.push({ type: events.length === 0 ? 'introduced' : 'reintroduced', commit, authorDate, scanId, observedAt });
  }
```

becomes:

```js
  for (const f of currentFindings) {
    if (!f.stableId) continue;
    const events = store[f.stableId] || (store[f.stableId] = []);
    if (isOpenEvent(events)) continue;
    const fp = f.findingProvenance;
    const commit = fp?.findingOrigin?.commit || null;
    const authorDate = fp?.status === 'complete' ? (fp.findingOrigin?.authorDate || observedAt) : observedAt;
    // M3 §3.1: a reintroduction whose resolved findingOrigin is a genuine
    // revert-of-a-fix or a cherry-picked propagation of an earlier
    // introduction is a DIFFERENT lifecycle story than an unrelated
    // reintroduction — both fields are only ever populated by deep-mode
    // resolution (Task 3), so this vocabulary is silent (both null) for
    // every standard-mode scan, which is the honest state: standard mode
    // has no opinion on the distinction.
    let type = events.length === 0 ? 'introduced' : 'reintroduced';
    if (fp?.findingOrigin?.revertOf) type = 'reverted';
    else if (fp?.findingOrigin?.cherryPickOf) type = 'cherry-picked';
    events.push({ type, commit, authorDate, scanId, observedAt });
  }
```

- [ ] **Step 2: Extend `isOpenEvent`**

Current:

```js
function isOpenEvent(events) {
  const last = events[events.length - 1];
  return !!last && (last.type === 'introduced' || last.type === 'reintroduced');
}
```

becomes:

```js
function isOpenEvent(events) {
  const last = events[events.length - 1];
  return !!last && ['introduced', 'reintroduced', 'reverted', 'cherry-picked'].includes(last.type);
}
```

- [ ] **Step 3: Write tests**

Append to `scanner/test/posture/provenance-lifecycle.test.js`. It already imports `createGitFixture`, `readLifecycle`, `updateLifecycle`, `latestOpenIntroduction` and builds findings as plain object literals (`{ stableId, findingProvenance: { status, findingOrigin: { commit, authorDate } } }`) with `createGitFixture()`/`try...finally { fx.cleanup(); }` — match that exact convention, not `emptyProvenance()`/`t.after`:

```js
test('applyScan: a finding whose findingOrigin.revertOf is set is classified "reverted", not "reintroduced"', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-revert',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: null, cherryPickOf: null },
      },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });

    const reintroduced = {
      stableId: 'sid-revert',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c2', authorDate: '2026-03-01T00:00:00Z', revertOf: 'c-fix', cherryPickOf: null },
      },
    };
    await updateLifecycle(fx.root, [reintroduced], { scanId: 'scan3', observedAt: '2026-03-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-revert'].length, 3);
    assert.equal(store['sid-revert'][2].type, 'reverted');
  } finally { fx.cleanup(); }
});

test('applyScan: a finding whose findingOrigin.cherryPickOf is set is classified "cherry-picked"', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-cherry',
      findingProvenance: {
        status: 'complete',
        findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: null, cherryPickOf: 'c-orig' },
      },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-cherry'][0].type, 'cherry-picked');
  } finally { fx.cleanup(); }
});

test('applyScan: neither revertOf nor cherryPickOf set — unchanged introduced/reintroduced behavior', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-plain', findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z' } } };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-plain'][0].type, 'introduced');
  } finally { fx.cleanup(); }
});

test('isOpenEvent: a "reverted" or "cherry-picked" last event is still open — remediation can close it', async () => {
  const fx = createGitFixture();
  try {
    const finding = {
      stableId: 'sid-open',
      findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z', revertOf: 'c-fix', cherryPickOf: null } },
    };
    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    let store = readLifecycle(fx.root);
    assert.equal(store['sid-open'][0].type, 'reverted');
    assert.ok(latestOpenIntroduction(store, 'sid-open'), 'a "reverted" event must count as open');

    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-open'][1].type, 'remediated', 'a reverted-open finding must still be remediable when it disappears');
  } finally { fx.cleanup(); }
});
```

- [ ] **Step 4: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-lifecycle.test.js` (foreground, timeout 60000). Expected: PASS, existing tests plus your 4 new ones.

- [ ] **Step 5: Run the broader scope and commit**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40` (foreground, timeout 600000). Expected: PASS.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/lifecycle.js scanner/test/posture/provenance-lifecycle.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): revert/cherry-pick lifecycle event classification (M3 §3.1)

applyScan reads the revertOf/cherryPickOf fields Task 3's deep-mode resolver
now populates and classifies the event as 'reverted'/'cherry-picked' instead
of a generic 'reintroduced' — silent (unchanged) for every standard-mode
scan, since only deep mode ever populates those fields.
EOF
)"
```

---

### Task 5: `engine.js` — propagate `depChain`, one-line fix

**Files:**
- Modify: `scanner/src/engine.js`
- Test: existing SCA tests (verify no regression; this is a pure additive field)

**Interfaces:**
- Produces: every `vulnerable_dep` finding object gains a `depChain: string[]` field (the CURRENT dependency ancestry, e.g. `['express', 'body-parser', 'qs']` for a transitive dependency; `[]` or `[name]` for a direct one) — currently computed at parse time and silently dropped before materialization.

- [ ] **Step 1: Find and read the exact materialization block**

Read `scanner/src/engine.js` around line 8210-8232 (the block the M3 research already identified, where `isDirect: comp.isDirect` is set) to get the EXACT current text — do not guess at surrounding lines, this codebase's `engine.js` is large and dense; confirm the precise object-literal shape before editing.

- [ ] **Step 2: Add the one-line fix**

Add `depChain: Array.isArray(comp.depChain) ? comp.depChain : [],` immediately adjacent to the existing `isDirect: comp.isDirect,` line in that same object literal (same object, sibling field — follow whatever exact formatting/comma convention the surrounding lines use). Note the research found `depChain` entries have a cosmetic trailing-slash artifact from the raw path split (`'express/'` not `'express'`) for non-last elements — clean this in the SAME line: `depChain: Array.isArray(comp.depChain) ? comp.depChain.map((s) => s.replace(/\/$/, '')) : [],`.

- [ ] **Step 3: Verify with a real scan**

Run: `cd scanner && npm run build 2>&1 | tail -20` (required, you touched `src/engine.js`).

Run a real scan against a fixture with a transitive vulnerable dependency (check `scanner/test/fixtures/` for an existing SCA fixture with nested `node_modules` entries in its `package-lock.json` — `sca-transitive-provenance` mentioned in this repo's own test fixtures directory is a strong candidate; if it doesn't exist yet, use any existing SCA test fixture and confirm at least one transitive `vulnerable_dep` finding is produced) and confirm `depChain` is now populated and cleaned (no trailing slashes) on transitive entries, empty/single-element on direct ones.

- [ ] **Step 4: Run the SCA test scope**

Run: `cd scanner && npm run test:posture 2>&1 | tail -60` (foreground, timeout 600000) — SCA tests are in this scope. Expected: PASS, no regression (this is a purely additive field; nothing existing reads or asserts its absence).

- [ ] **Step 5: Add a regression test**

In whichever existing SCA test file already exercises `_parsePackageLockJson`/transitive dependency materialization (search `scanner/test/` for a test asserting `isDirect` on a `vulnerable_dep` finding — the fix this task mirrors — and add `depChain` assertions alongside the existing `isDirect` assertions in that SAME test, rather than writing a new file), add: for a known transitive dependency in the fixture, assert `finding.depChain` is a non-empty array of clean (no trailing-slash) package names ending in the vulnerable package's own name; for a known direct dependency, assert `depChain.length <= 1`.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/engine.js scanner/dist/ scanner/test/
git commit -m "$(cat <<'EOF'
fix(sca): propagate depChain onto vulnerable_dep findings (M3 §3.2 prereq)

Mirrors the earlier isDirect propagation fix — depChain was computed by the
lockfile parser but silently dropped before reaching the finding object.
Task 6's transitive-sca.js uses this as a starting hint (the CURRENT
ancestry), though it still must re-derive ancestry at each historical
candidate commit since the dependency graph's shape can itself change
across commits.
EOF
)"
```

---

### Task 6: `transitive-sca.js` — transitive dependency origin resolution

**Files:**
- Create: `scanner/src/posture/provenance/transitive-sca.js`
- Test: `scanner/test/posture/provenance-transitive-sca.test.js`

**Interfaces:**
- Produces: `resolveTransitiveSCAOrigin(scanRoot, scaEntry, { since, deadlineAt } = {})` — same return shape as `sca-origin.js`'s `resolveDirectSCAOrigin` (`{status, method, commitsConsidered, findingOrigin?, reason?, parentBoundaryVerified?}`), so `coordinator.js` (Task 7) can dispatch to either uniformly.
- Consumes: `candidateCommitsForFile`, `getFirstParent`, `getBlobAtCommit`, `commitMeta` (existing `git-evidence.js` exports — same as `sca-origin.js` already uses), `versionInRange` (exported from `sca-origin.js`, reused not reimplemented per the spec).

**Scope note (read before implementing):** this task targets **npm (`package-lock.json`) only** for M3. The spec's own §3.2 doesn't name a specific lockfile format, and this codebase's research confirmed `package-lock.json`'s `packages` key is the one format whose parser (`_parsePackageLockJson`, `engine.js`) already extracts clean path-derived ancestry. Extending to `yarn.lock`/`pnpm-lock.yaml`/other ecosystems' lockfiles is a documented, deliberate scope line — each has a different on-disk structure requiring its own historical-blob ancestry extraction, and attempting all of them in one task risks a shallow, undertested implementation across five formats instead of one well-tested one. `resolveTransitiveSCAOrigin` returns `not_available` with an explicit `reason: 'unsupported-lockfile-format'` for any non-`package-lock.json` transitive entry — never silently wrong, never a guess.

- [ ] **Step 1: Write `transitive-sca.js`**

```js
// Transitive dependency origin resolution (Finding Provenance PRD, M3 §3.2).
//
// A transitive vulnerable_dep finding's vulnerable version was never
// declared directly in this repo's manifest — some DIRECT dependency's
// version bump pulled it into the graph. This module answers "which commit
// changed the lockfile such that the vulnerable transitive version first
// appears," re-deriving the dependency's ancestry AT EACH HISTORICAL
// CANDIDATE COMMIT rather than trusting the CURRENT depChain (Task 5) —
// the graph's shape can itself change across commits, so the current
// ancestry is a hint for the fixture/test author, not evidence a resolver
// can rely on for a historical claim.
//
// Scope: package-lock.json only for M3 — see the plan's Task 6 scope note.

import { candidateCommitsForFile, getFirstParent, getBlobAtCommit, commitMeta } from './git-evidence.js';
import { versionInRange } from './sca-origin.js';
import { PROVENANCE_METHOD } from './schema.js';

const LOCKFILE_BASENAME = 'package-lock.json';

// Extract {version, depChain} for `depName` from a package-lock.json blob's
// text, using the same `packages` key structure engine.js's
// _parsePackageLockJson reads at scan time (lockfile v2/v3 shape: keys are
// paths like "node_modules/express/node_modules/qs"). Returns null if the
// package isn't present in this blob at all (e.g., an OLDER lockfile before
// it was ever pulled in).
function extractTransitiveVersion(blobText, depName) {
  let doc;
  try { doc = JSON.parse(blobText); } catch { return null; }
  const packages = doc.packages;
  if (!packages || typeof packages !== 'object') return null;
  // Prefer the SHORTEST matching path (closest to a direct dependency) when
  // multiple nested copies of the same package exist at different depths —
  // matches the ancestry a reader would consider "the" instance most of the
  // time. Ties resolve to whichever JSON.stringify/Object.keys ordering
  // returns first (lockfiles preserve insertion order; this is deterministic
  // for a given blob, which is what matters for a repeatable resolution).
  let best = null;
  for (const key of Object.keys(packages)) {
    if (!key.endsWith(`node_modules/${depName}`)) continue;
    const depChain = key.split('node_modules/').filter(Boolean).map((s) => s.replace(/\/$/, ''));
    const entry = packages[key];
    const version = entry && entry.version;
    if (!version) continue;
    if (!best || depChain.length < best.depChain.length) best = { version, depChain };
  }
  return best;
}

function originResult({ meta, commitsConsidered, depChain }) {
  return {
    status: 'complete', method: PROVENANCE_METHOD.DEPENDENCY_GRAPH_DIFF, commitsConsidered,
    findingOrigin: {
      commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
      authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
      presentInCommit: true, absentInParents: [], revertOf: null, cherryPickOf: null,
    },
    parentBoundaryVerified: true,
    depChain,
  };
}

export async function resolveTransitiveSCAOrigin(scanRoot, scaEntry, { since, deadlineAt } = {}) {
  const file = scaEntry.filePath || scaEntry.file;
  if (!file) return { status: 'not_available', reason: 'no-manifest-path', commitsConsidered: 0 };
  const basename = file.split('/').pop();
  if (basename !== LOCKFILE_BASENAME) {
    return { status: 'not_available', reason: 'unsupported-lockfile-format', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForFile(scanRoot, file, { since });
  if (candidates.length === 0) return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };

  const range = { introduced: null, fixed: (scaEntry.fixedVersions || [])[0] || null };
  let commitsConsidered = 0;
  let rootFallback = null;
  let rootFallbackChain = null;
  let ambiguousBump = false;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    const blob = getBlobAtCommit(scanRoot, sha, file);
    if (blob == null) continue;
    const declared = extractTransitiveVersion(blob, scaEntry.name);
    if (!declared || !versionInRange(declared.version, range)) continue;

    const parent = getFirstParent(scanRoot, sha);
    if (!parent) {
      if (!rootFallback) {
        const meta = commitMeta(scanRoot, sha);
        if (meta) { rootFallback = meta; rootFallbackChain = declared.depChain; }
      }
      continue;
    }

    const parentBlob = getBlobAtCommit(scanRoot, parent, file);
    const parentDeclared = parentBlob ? extractTransitiveVersion(parentBlob, scaEntry.name) : null;
    const parentOutOfRange = !parentDeclared || !versionInRange(parentDeclared.version, range);
    if (!parentOutOfRange) {
      // Same ambiguity sca-origin.js's resolveDirectSCAOrigin documents: a
      // fixed-only range with no lower bound can't distinguish "vulnerable
      // since inception, unrelated bump" from "just became vulnerable here."
      if (parentDeclared.version !== declared.version) ambiguousBump = true;
      continue;
    }

    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;
    return originResult({ meta, commitsConsidered, depChain: declared.depChain });
  }

  if (rootFallback && !ambiguousBump) {
    return originResult({ meta: rootFallback, commitsConsidered, depChain: rootFallbackChain });
  }

  return {
    status: 'partial',
    reason: ambiguousBump ? 'ambiguous-range-no-introduced-bound' : 'version-never-confirmed-in-candidates',
    commitsConsidered,
  };
}
```

- [ ] **Step 2: Write tests using a real synthetic lockfile fixture**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTransitiveSCAOrigin } from '../../src/posture/provenance/transitive-sca.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

function lockfile(depsWithVersions) {
  // Minimal v2/v3-shaped package-lock.json: top-level "" entry (the root
  // package) plus one entry per dependency at a NESTED path to simulate a
  // transitive dependency (not a direct one, which would live at
  // "node_modules/<name>" with no further nesting under a direct parent).
  const packages = { '': { name: 'root', version: '1.0.0' } };
  for (const [pathSuffix, version] of Object.entries(depsWithVersions)) {
    packages[`node_modules/${pathSuffix}`] = { version };
  }
  return JSON.stringify({ name: 'root', lockfileVersion: 3, packages }, null, 2);
}

test('resolveTransitiveSCAOrigin: resolves the commit that bumped a transitive dep into the vulnerable range', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('package-lock.json', lockfile({ 'express/node_modules/qs': '6.5.0' }));
  fx.commit('safe qs version');
  fx.writeFile('package-lock.json', lockfile({ 'express/node_modules/qs': '6.5.3' }));
  const bumpSha = fx.commit('bump qs to vulnerable version');

  const scaEntry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.3'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'complete');
  assert.equal(result.findingOrigin.commit, bumpSha);
  assert.deepEqual(result.depChain, ['express', 'qs']);
});

test('resolveTransitiveSCAOrigin: an unsupported lockfile format resolves not_available with an explicit reason, never a guess', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('yarn.lock', 'qs@6.5.3:\n  version "6.5.3"\n');
  fx.commit('yarn lockfile');
  const scaEntry = { name: 'qs', filePath: 'yarn.lock', fixedVersions: ['6.5.3'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'not_available');
  assert.equal(result.reason, 'unsupported-lockfile-format');
});

test('resolveTransitiveSCAOrigin: no candidate history resolves not_available, never fabricates', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('other.txt', 'x');
  fx.commit('unrelated');
  const scaEntry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.3'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'not_available');
  assert.equal(result.reason, 'no-candidate-commits');
});
```

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-transitive-sca.test.js` (foreground, timeout 60000). Expected: PASS, 3/3.

- [ ] **Step 4: Add to `test:posture` and commit**

Insert into `scanner/package.json`'s `"test:posture"` script.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/transitive-sca.js scanner/test/posture/provenance-transitive-sca.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): transitive SCA dependency origin resolution (M3 §3.2)

resolveTransitiveSCAOrigin walks package-lock.json's history re-deriving
ancestry at each candidate commit (never trusting only the current depChain,
since the graph's shape can itself change across commits). Scoped to npm's
lockfile format for M3 — other ecosystems return an explicit
unsupported-lockfile-format reason, never a guess.
EOF
)"
```

---

### Task 7: `coordinator.js` — wire transitive SCA into the annotation pass

**Files:**
- Modify: `scanner/src/posture/provenance/coordinator.js`
- Modify: `scanner/src/engine.js` (the backstop block from this plan's research, lines ~10206-10321)
- Test: `scanner/test/posture/provenance-coordinator.test.js` (extend), `scanner/test/posture/provenance-coordinator-sca.test.js` (extend)

**Interfaces:**
- Produces: `annotateGitProvenance(findings, {..., findingType: 'sca-transitive'})` — a third `findingType` value, alongside the existing default (SAST) and `'sca'` (direct dependency).
- Consumes: `resolveTransitiveSCAOrigin` (Task 6).

- [ ] **Step 1: Extend `coordinator.js`'s three-way branch**

In `scanner/src/posture/provenance/coordinator.js`, add the import:

```js
import { resolveDirectSCAOrigin, scaStableId } from './sca-origin.js';
```

becomes:

```js
import { resolveDirectSCAOrigin, scaStableId } from './sca-origin.js';
import { resolveTransitiveSCAOrigin } from './transitive-sca.js';
```

In `resolveOne`, the current:

```js
  const isSca = ctx.findingType === 'sca';
```

becomes:

```js
  const isSca = ctx.findingType === 'sca';
  const isTransitiveSca = ctx.findingType === 'sca-transitive';
  // Both direct and transitive SCA entries share the same non-SAST shape —
  // no file+line to blame, stableId backfilled the same way. Only WHICH
  // resolver runs (Task 6 vs sca-origin.js) and what evidence/detector
  // label gets attached differ between them.
  const isScaLike = isSca || isTransitiveSca;
```

Every subsequent `isSca` reference that gates the SAST-vs-SCA-SHAPE distinction (the uncommitted-blame skip, the stableId backfill) changes to `isScaLike`:

```js
  if (!isSca && finding.file && finding.line) {
```

becomes:

```js
  if (!isScaLike && finding.file && finding.line) {
```

and:

```js
  if (isSca && !finding.stableId) {
    finding.stableId = scaStableId(finding);
  }
```

becomes:

```js
  if (isScaLike && !finding.stableId) {
    finding.stableId = scaStableId(finding);
  }
```

`resolveOne`'s call into `resolveAndCache` passes `isSca` positionally — change to pass `isScaLike`'s two constituent flags through `ctx` instead (simpler than adding a fourth positional param): the memo/dispatch code

```js
  const promise = resolveAndCache(finding, ctx, cacheKey, isSca);
```

becomes:

```js
  const promise = resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca);
```

In `resolveAndCache`, the signature and the origin-resolution dispatch:

```js
async function resolveAndCache(finding, ctx, cacheKey, isSca) {
  const { scanRoot, repoState, deadlineAt } = ctx;
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;
  ...
  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState, mode: ctx.mode });

  const detector = isSca ? SCA_DETECTOR : (finding.parser || null);
```

becomes:

```js
async function resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca) {
  const { scanRoot, repoState, deadlineAt } = ctx;
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;
  ...
  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : isTransitiveSca
    ? await resolveTransitiveSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState, mode: ctx.mode });

  const detector = isSca ? SCA_DETECTOR : isTransitiveSca ? TRANSITIVE_SCA_DETECTOR : (finding.parser || null);
```

Add the new detector label constant next to the existing one:

```js
const SCA_DETECTOR = 'sca-manifest-diff';
```

becomes:

```js
const SCA_DETECTOR = 'sca-manifest-diff';
const TRANSITIVE_SCA_DETECTOR = 'sca-lockfile-history-diff';
```

The `evidenceAttribution` ternary — currently `isSca ? [...manifest node...] : attributeEvidence(...)` — becomes `isSca || isTransitiveSca ? [...] : attributeEvidence(...)` (both SCA kinds get the same single-manifest-node evidence shape; `isScaLike` reads more clearly here than repeating the OR):

```js
    const evidenceAttribution = isSca
      ? [{
```

becomes:

```js
    const evidenceAttribution = isScaLike
      ? [{
```

(Note: `isScaLike` is computed in `resolveOne`, not `resolveAndCache` — `resolveAndCache` needs its own local `const isScaLike = isSca || isTransitiveSca;` at the top of the function, since the two functions don't share scope.)

`resolveTransitiveSCAOrigin`'s return object carries a `depChain` field (Task 6) that nothing currently reads — wire it into the evidence node so it doesn't go silently unused. The manifest-node evidence object (inside the `isScaLike ? [{...}]` block) currently has shape `{role: EVIDENCE_ROLE.MANIFEST, path, line, commit}`; add one more field, populated only for the transitive case:

```js
    const evidenceAttribution = isScaLike
      ? [{
          role: EVIDENCE_ROLE.MANIFEST,
          path: finding.filePath || null,
          line: Number.isInteger(finding.line) ? finding.line : null,
          commit: originResult.findingOrigin.commit,
          depChain: isTransitiveSca && Array.isArray(originResult.depChain) ? originResult.depChain : null,
        }]
      : attributeEvidence(scanRoot, finding);
```

- [ ] **Step 2: Rewire `engine.js`'s backstop to call the transitive resolver**

Read the exact current block at `scanner/src/engine.js` around lines 10206-10222 (the `directDeps` filter + `annotateGitProvenance(directDeps, ...)` call) to confirm exact current text, then add a parallel block for transitive deps immediately after it:

```js
    const directDeps = (supplyChain || []).filter((s) => s && s.type === 'vulnerable_dep' && s.isDirect);
    for (const s of directDeps) { if (!s.filePath && s.file) s.filePath = s.file; }
    await annotateGitProvenance(directDeps, { ...provenanceCtx, findingType: 'sca' });
    // M3 §3.2: transitive dependencies now get real origin resolution too,
    // narrowing what was previously an unconditional not_available backstop
    // to genuinely unresolvable cases (non-npm lockfiles, no candidate
    // history) — see transitive-sca.js's own scope note.
    const transitiveDeps = (supplyChain || []).filter((s) => s && s.type === 'vulnerable_dep' && !s.isDirect);
    for (const s of transitiveDeps) { if (!s.filePath && s.file) s.filePath = s.file; }
    await annotateGitProvenance(transitiveDeps, { ...provenanceCtx, findingType: 'sca-transitive' });
```

Then find the backstop loop later in the same function (the one this plan's research already located, with the `sc.type === 'vulnerable_dep' ? 'transitive dependency origin resolution is not implemented...' : ...` ternary) and simplify it — since `transitiveDeps` above now already stamps `findingProvenance` on every transitive entry (either a real resolution or `resolveTransitiveSCAOrigin`'s own honest `not_available`/`partial`), the backstop loop's `if (!sc.findingProvenance)` guard means it will naturally skip every entry this new pass already touched, and only the truly-untouched cases (a transitive dep whose `annotateGitProvenance` call itself threw before reaching it, or a non-`vulnerable_dep` supplyChain type) still fall through. Update the STALE comment text (the one claiming "the resolver is deliberately not run") so it doesn't contradict the code two lines above it — read the exact current comment block and replace the now-inaccurate sentence about transitive deps being unimplemented with: `transitive vulnerable_deps: resolved by resolveTransitiveSCAOrigin above (M3 §3.2) — this branch is now reached only if that annotation pass itself failed to stamp the entry.`

- [ ] **Step 3: Run and verify**

Run: `cd scanner && npm run build 2>&1 | tail -20`.
Run: `cd scanner && node --test test/posture/provenance-coordinator.test.js test/posture/provenance-coordinator-sca.test.js test/posture/provenance-transitive-sca.test.js` (foreground, timeout 120000). Expected: PASS.

- [ ] **Step 4: Add a coordinator-level integration test**

Append to `scanner/test/posture/provenance-coordinator-sca.test.js` (follow its existing fixture-construction conventions):

```js
test('annotateGitProvenance: findingType "sca-transitive" resolves via resolveTransitiveSCAOrigin, not resolveDirectSCAOrigin', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  const lockfile = (v) => JSON.stringify({ name: 'root', lockfileVersion: 3, packages: { '': {}, [`node_modules/express/node_modules/qs`]: { version: v } } });
  fx.writeFile('package-lock.json', lockfile('6.5.0'));
  fx.commit('safe');
  fx.writeFile('package-lock.json', lockfile('6.5.3'));
  fx.commit('vulnerable bump');

  const entry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.3'], isDirect: false };
  const findings = [entry];
  await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: new Date().toISOString(), findingType: 'sca-transitive' });
  assert.equal(entry.findingProvenance.status, 'complete');
  assert.equal(entry.findingProvenance.analysisBasis.detector, 'sca-lockfile-history-diff');
});
```

- [ ] **Step 5: Run the broader scope**

Run: `cd scanner && npm run test:posture 2>&1 | tail -60` (foreground, timeout 600000). Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/coordinator.js scanner/src/engine.js scanner/dist/ scanner/test/posture/provenance-coordinator-sca.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): wire transitive SCA resolution into the annotation pass (M3 §3.2)

coordinator.js gains a third findingType ('sca-transitive'), and engine.js
now runs a real resolution pass over transitive vulnerable_dep entries
instead of unconditionally stamping them not_available. The backstop's
comment is corrected to match — it no longer claims the resolver "is
deliberately not run."
EOF
)"
```

---

### Task 8: `providers/{github,gitlab}.js` — opt-in provider enrichment

**Files:**
- Create: `scanner/src/posture/provenance/providers/github.js`
- Create: `scanner/src/posture/provenance/providers/gitlab.js`
- Test: `scanner/test/posture/provenance-providers.test.js`

**Interfaces:**
- Produces: both modules export the SAME two-function interface: `fetchPRMetadata(commitSha, config)` returning `Promise<{prNumber, reviewers, approvals, mergedAt}|null>` (`null` when unresolvable — no PR found, network error, or not configured), and `fetchCodeowners(config)` returning `Promise<string[]|null>` (list of CODEOWNERS patterns/owners, or `null`).
- Config resolution (both modules share this): opt-in via EITHER an env var (`AGENTIC_SECURITY_GITHUB_TOKEN` / `AGENTIC_SECURITY_GITLAB_TOKEN`) OR `.agentic-security/provenance-providers.yml` (parsed via the existing `util/yaml.js` shim) naming `{provider, token, baseUrl?}`. With neither present, both functions return `null` immediately with ZERO network calls — the hermeticity property this task's test proves.

- [ ] **Step 1: Write the shared config resolver**

Create `scanner/src/posture/provenance/providers/config.js`:

```js
// Shared opt-in config resolution for provider enrichment (Finding
// Provenance PRD, M3 §3.4). Strictly opt-in: with neither an env var nor a
// config file present, resolveProviderConfig returns null and NEITHER
// providers/github.js nor providers/gitlab.js makes any network call —
// this is the property provenance-providers.test.js's hermeticity test
// proves. Modeled on llm-validator/index.js's existing
// AGENTIC_SECURITY_LLM_ENDPOINT precedent (opt-in via env var, degrades to
// a no-op when unset) rather than inventing a new convention.
import * as fs from 'node:fs';
import { statePath } from '../../state-dir.js';
import { load as loadYaml } from '../../../util/yaml.js';

const ENV_VAR_BY_PROVIDER = { github: 'AGENTIC_SECURITY_GITHUB_TOKEN', gitlab: 'AGENTIC_SECURITY_GITLAB_TOKEN' };

/**
 * `provider` is 'github' | 'gitlab'. Returns {token, baseUrl} or null.
 * Env var wins if both are present — the same "explicit beats inferred"
 * precedent config-resolution follows elsewhere in this codebase (e.g.
 * state-dir.js's caller-supplied-scanRoot-wins-over-cwd-walk).
 */
export function resolveProviderConfig(scanRoot, provider) {
  const envVar = ENV_VAR_BY_PROVIDER[provider];
  const envToken = envVar ? process.env[envVar] : undefined;
  if (envToken) return { token: envToken, baseUrl: null };

  // .agentic-security/provenance-providers.yml — NOT gated behind
  // stateWritesEnabled()/isSafeStateDir() the way STATE WRITES are; this is
  // a READ of an operator-authored config file, the same class of read
  // rules.yml already performs unconditionally.
  const configPath = statePath(scanRoot, 'provenance-providers.yml');
  let text;
  try { text = fs.readFileSync(configPath, 'utf8'); } catch { return null; }
  let doc;
  try { doc = loadYaml(text); } catch { return null; }
  if (!doc || typeof doc !== 'object') return null;
  const entry = doc[provider];
  if (!entry || !entry.token) return null;
  return { token: entry.token, baseUrl: entry.baseUrl || null };
}
```

- [ ] **Step 2: Write `providers/github.js`**

```js
// GitHub provider enrichment (Finding Provenance PRD, M3 §3.4). Strictly
// opt-in — see config.js's resolveProviderConfig. Every export returns null
// immediately, with zero network calls, when unconfigured.
import { resolveProviderConfig } from './config.js';

const DEFAULT_API_BASE = 'https://api.github.com';

function ownerRepoFromRemote(remoteUrl) {
  // Handles both "git@github.com:owner/repo.git" and
  // "https://github.com/owner/repo.git" — the two forms `git remote -v`
  // actually produces.
  const m = String(remoteUrl || '').match(/github\.com[:/]([^/]+)\/([^/.]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

export async function fetchPRMetadata(scanRoot, commitSha, remoteUrl, config) {
  if (!config || !config.token) return null;
  const or = ownerRepoFromRemote(remoteUrl);
  if (!or) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  try {
    const r = await fetch(`${base}/repos/${or.owner}/${or.repo}/commits/${commitSha}/pulls`, {
      headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
    });
    if (!r.ok) return null;
    const prs = await r.json();
    if (!Array.isArray(prs) || prs.length === 0) return null;
    const pr = prs[0];
    return {
      prNumber: pr.number,
      reviewers: (pr.requested_reviewers || []).map((u) => u.login),
      approvals: null, // GitHub's PR-list-by-commit endpoint doesn't include review state; a real approvals count needs a second call, deliberately not made here to keep this a single-request enrichment.
      mergedAt: pr.merged_at || null,
    };
  } catch {
    return null;
  }
}

export async function fetchCodeowners(scanRoot, remoteUrl, config) {
  if (!config || !config.token) return null;
  const or = ownerRepoFromRemote(remoteUrl);
  if (!or) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  for (const path of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    try {
      const r = await fetch(`${base}/repos/${or.owner}/${or.repo}/contents/${path}`, {
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
      });
      if (!r.ok) continue;
      const body = await r.json();
      if (!body.content) continue;
      const text = Buffer.from(body.content, 'base64').toString('utf8');
      return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    } catch { continue; }
  }
  return null;
}

export { resolveProviderConfig };
```

- [ ] **Step 3: Write `providers/gitlab.js`**

```js
// GitLab provider enrichment (Finding Provenance PRD, M3 §3.4). Same
// contract as providers/github.js — strictly opt-in, zero network calls
// when unconfigured.
import { resolveProviderConfig } from './config.js';

const DEFAULT_API_BASE = 'https://gitlab.com/api/v4';

function projectPathFromRemote(remoteUrl) {
  const m = String(remoteUrl || '').match(/gitlab\.com[:/](.+?)(?:\.git)?$/);
  return m ? m[1] : null;
}

export async function fetchPRMetadata(scanRoot, commitSha, remoteUrl, config) {
  if (!config || !config.token) return null;
  const projectPath = projectPathFromRemote(remoteUrl);
  if (!projectPath) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  const encodedProject = encodeURIComponent(projectPath);
  try {
    const r = await fetch(`${base}/projects/${encodedProject}/repository/commits/${commitSha}/merge_requests`, {
      headers: { 'PRIVATE-TOKEN': config.token },
    });
    if (!r.ok) return null;
    const mrs = await r.json();
    if (!Array.isArray(mrs) || mrs.length === 0) return null;
    const mr = mrs[0];
    return {
      prNumber: mr.iid,
      reviewers: (mr.reviewers || []).map((u) => u.username),
      approvals: typeof mr.upvotes === 'number' ? mr.upvotes : null,
      mergedAt: mr.merged_at || null,
    };
  } catch {
    return null;
  }
}

export async function fetchCodeowners(scanRoot, remoteUrl, config) {
  if (!config || !config.token) return null;
  const projectPath = projectPathFromRemote(remoteUrl);
  if (!projectPath) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  const encodedProject = encodeURIComponent(projectPath);
  try {
    const r = await fetch(`${base}/projects/${encodedProject}/repository/files/CODEOWNERS/raw?ref=HEAD`, {
      headers: { 'PRIVATE-TOKEN': config.token },
    });
    if (!r.ok) return null;
    const text = await r.text();
    return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  } catch {
    return null;
  }
}

export { resolveProviderConfig };
```

- [ ] **Step 4: Write the hermeticity test**

```js
// M3 §3.4: providers must make ZERO network calls when unconfigured. Spy on
// global.fetch, matching llm-validator-default-on.test.js's existing
// precedent (scanner/test/llm-validator-default-on.test.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { resolveProviderConfig } from '../../src/posture/provenance/providers/config.js';
import * as github from '../../src/posture/provenance/providers/github.js';
import * as gitlab from '../../src/posture/provenance/providers/gitlab.js';

function withEnv(vars, fn) {
  const prior = {};
  for (const k of Object.keys(vars)) prior[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return Promise.resolve(fn()).finally(() => {
    for (const [k, v] of Object.entries(prior)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });
}

test('resolveProviderConfig: returns null with no env var and no config file present', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    assert.equal(resolveProviderConfig(tmp, 'github'), null);
    assert.equal(resolveProviderConfig(tmp, 'gitlab'), null);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('resolveProviderConfig: env var wins, no file needed', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: 'ghp_test123' }, () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      assert.equal(cfg.token, 'ghp_test123');
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('github.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      const pr = await github.fetchPRMetadata(tmp, 'abc123', 'https://github.com/owner/repo.git', cfg);
      const owners = await github.fetchCodeowners(tmp, 'https://github.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('gitlab.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'gitlab');
      const pr = await gitlab.fetchPRMetadata(tmp, 'abc123', 'https://gitlab.com/owner/repo.git', cfg);
      const owners = await gitlab.fetchCodeowners(tmp, 'https://gitlab.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('github.fetchPRMetadata: configured, makes exactly one fetch call and parses a real-shaped response', async () => {
  const priorFetch = global.fetch;
  let callCount = 0;
  global.fetch = async (url) => {
    callCount++;
    assert.match(url, /\/commits\/abc123\/pulls$/);
    return {
      ok: true,
      json: async () => ([{ number: 42, requested_reviewers: [{ login: 'alice' }], merged_at: '2026-01-01T00:00:00Z' }]),
    };
  };
  try {
    const pr = await github.fetchPRMetadata('/tmp', 'abc123', 'https://github.com/owner/repo.git', { token: 'x', baseUrl: null });
    assert.equal(pr.prNumber, 42);
    assert.deepEqual(pr.reviewers, ['alice']);
    assert.equal(callCount, 1);
  } finally { global.fetch = priorFetch; }
});
```

- [ ] **Step 5: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-providers.test.js` (foreground, timeout 60000). Expected: PASS, 6/6.

- [ ] **Step 6: Add to `test:posture` and commit**

Insert into `scanner/package.json`'s `"test:posture"` script.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/providers/ scanner/test/posture/provenance-providers.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): opt-in GitHub/GitLab provider enrichment (M3 §3.4)

fetchPRMetadata/fetchCodeowners for both providers, gated on an env var or
.agentic-security/provenance-providers.yml — zero network calls with
neither present, proven by a fetch-spy hermeticity test mirroring
llm-validator's existing precedent. Not yet wired into the coordinator's
annotation pass — this task builds the capability; a future milestone
decides how findingProvenance surfaces it.
EOF
)"
```

---

### Task 9: Rename fixture + honesty test (FR-PROV-007 completion)

**Files:**
- Test: `scanner/test/posture/provenance-origin-resolver.test.js` (extend)

**Scope correction (see the plan-level note above):** `origin-resolver.js` calls `candidateCommitsForLine`, which has NO `--follow` flag — the spec's own text referencing `candidateCommitsForFile`'s `--follow` here was a factual error caught during this plan's research. This task tests `candidateCommitsForLine`'s REAL behavior at a rename boundary (with no code change proposed a priori) and requires the implementer to investigate before writing the final assertion.

- [ ] **Step 1: Build the rename fixture and observe actual behavior**

Write a test fixture: a file `old-name.js` containing a vulnerable pattern, committed; then `git mv old-name.js new-name.js` (equivalent: write `new-name.js` with identical content, `git rm old-name.js`, commit both in one commit) to simulate a rename; then run `resolveOrigin` against the finding as it appears in `new-name.js` post-rename.

```js
test('resolveOrigin: a file renamed after introduction is handled honestly — either the pre-rename origin is found, or an explicit reason is reported, never silently lost', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('old-name.js', 'safe();\n');
  fx.commit('safe baseline');
  fx.writeFile('old-name.js', 'eval(x);\n');
  const introduced = fx.commit('introduce eval in old-name.js');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['mv', 'old-name.js', 'new-name.js'], { cwd: fx.root });
  execFileSync('git', ['commit', '-m', 'rename old-name.js to new-name.js'], { cwd: fx.root });

  const { computeStableId } = await import('../../src/posture/stable-id.js');
  const finding = { file: 'new-name.js', line: 1, ruleId: 'no-eval', vuln: 'eval() Injection' };
  finding.stableId = computeStableId(finding);

  const result = await resolveOrigin(fx.root, finding, {});
  // INVESTIGATE FIRST, then keep exactly ONE of these two assertion blocks
  // (delete the other) based on what candidateCommitsForLine ACTUALLY does
  // at a rename boundary — do not guess, run this test with a console.log
  // of `result` first and observe:
  //
  // OUTCOME A: candidateCommitsForLine, scoped to the CURRENT path
  // ('new-name.js'), finds no candidates before the rename commit (git log
  // -L without --follow does not cross a rename) — the walk resolves
  // 'partial' or 'not_available' with an explicit reason, honestly
  // reporting it could not see past the rename, NOT silently misattributing
  // origin to the rename commit itself as if that were the introduction.
  assert.notEqual(result.status, 'complete', 'must not misattribute the origin to the rename commit — if this fails, candidateCommitsForLine crossed the rename boundary and OUTCOME B (below) is the real behavior instead');
  assert.ok(['partial', 'not_available'].includes(result.status));
  //
  // OUTCOME B (if the assertion above fails when you run this): git's -L
  // actually did follow the rename in this git version/scenario — in that
  // case replace the block above with:
  //   assert.equal(result.status, 'complete');
  //   assert.match(result.findingOrigin.summary, /introduce eval/);
  // and delete the notEqual/status-partial assertions instead. Either
  // outcome is an ACCEPTABLE resolution of this task — what is NOT
  // acceptable is a result.status of 'complete' pointing at the WRONG
  // commit (e.g. the rename commit itself, which never introduced the
  // vulnerable pattern, only moved it).
});
```

- [ ] **Step 2: Run, observe, finalize the assertion**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js` (foreground, timeout 60000) with the test above added and a temporary `console.log(JSON.stringify(result, null, 2))` inserted. Read the actual `result` shape, delete the console.log, and keep exactly the correct outcome block (A or B) per the instructions in the test's own comments above. If the observed behavior is NEITHER honest-partial NOR correctly-complete — i.e., it silently reports `'complete'` pointing at the wrong commit — this IS a real bug: do not paper over it with a passing assertion. Instead, add a minimal fix to `origin-resolver.js`: when `candidateCommitsForLine` returns a non-empty list but the OLDEST candidate's `commitMeta().summary` doesn't plausibly correspond to introducing the pattern (this is a weak heuristic — prefer instead checking whether `getBlobAtCommit` at the oldest candidate already contains the vulnerable pattern with no earlier candidate to explain it, i.e. `commitsConsidered === candidates.length` and the walk fell through to the `partial` return, which is likely already report a `reason` distinguishing "genuinely no earlier candidate exists" from "candidates ran out because the file's tracked history is short" — these need a `reason: 'possible-untracked-rename-boundary'` addition if the existing reasons don't already distinguish them). Document whichever real outcome you found in the fix-loop / task report rather than guessing here.

- [ ] **Step 3: Run the full test file and broader scope**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js` (foreground, timeout 60000). Expected: PASS.
Run: `cd scanner && npm run test:posture 2>&1 | tail -40` (foreground, timeout 600000). Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/test/posture/provenance-origin-resolver.test.js
# If Step 2 required a production fix:
# git add scanner/src/posture/provenance/origin-resolver.js
git commit -m "$(cat <<'EOF'
test(provenance): rename-boundary honesty (M3 §3.5 / FR-PROV-007)

Proves origin-resolver never misattributes a finding's origin to a rename
commit — either it honestly reports it can't see past the rename boundary,
or (if the observed git behavior crosses it) correctly resolves the true
pre-rename origin. Corrects a factual error in the design spec's own text,
which named candidateCommitsForFile (the SCA/direct-dependency helper) when
origin-resolver.js actually uses candidateCommitsForLine (no --follow).
EOF
)"
```

---

### Task 10: `missing-control-resolver.js` — presence→absence resolution

**Files:**
- Create: `scanner/src/posture/provenance/missing-control-resolver.js`
- Test: `scanner/test/posture/provenance-missing-control-resolver.test.js`

**Scope (see the plan-level note above):** no existing detector/finding type in this codebase represents "a control that was present and is now absent" — this ships as a standalone, thoroughly-tested library module, not wired into `engine.js`'s live pipeline. A future milestone can wire it once a real caller (a detector, or `evidence-attribution.js`'s currently-dead `REMOVED_GUARD` path) exists.

**Interfaces:**
- Produces: `resolveMissingControl(scanRoot, { file, predicate, since, deadlineAt } = {})` — `predicate` is a caller-supplied `(scanRoot, sha, file) => Promise<boolean>` function answering "is the control present in this file at this commit" (matching `predicate-replay.js`'s own "replay the detector, compare" shape, but generalized since a missing-control caller isn't necessarily a `stableId`-keyed SAST finding — could be "does this file contain a rate-limit decorator," "does CODEOWNERS require review of this path," etc.). Returns `{status: 'complete'|'unknown'|'budget_exhausted', removedAt?: {commit,authorName,authorDate,summary}, presentAt?: {commit,authorDate}, commitsConsidered}`.

- [ ] **Step 1: Write `missing-control-resolver.js`**

```js
// Missing-control regression resolution (Finding Provenance PRD, M3 §3.3).
//
// Architecturally inverted from every other resolver in this directory:
// "when did a previously-observed safeguard DISAPPEAR," not "when did a bad
// pattern APPEAR." Walks backward from HEAD (newest-first — the opposite
// direction candidateCommitsForLine's oldest-first convention uses, because
// this resolver is searching for the MOST RECENT transition from present to
// absent, not the earliest transition from absent to present).
//
// The one invariant this module exists to enforce, verbatim from the spec:
// if the control is absent at EVERY reachable commit including the
// repository's own root, status is 'unknown' — NEVER attributed to the root
// commit. Every other resolver in this milestone treats "absent at the
// root, present now" as real evidence of introduction (the root IS the
// beginning of everything this repo can prove). This resolver's question is
// the mirror image — "when did it disappear" — and a control absent
// EVERYWHERE has no disappearance to date, which is a fundamentally
// different, weaker claim than "introduced at the beginning." Collapsing
// them would be exactly the false certainty the whole feature forbids.

import { getFirstParent, commitMeta } from './git-evidence.js';
import * as cp from 'node:child_process';

const GIT_TIMEOUT_MS = 2000;
function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '', error: e };
  }
}

// The commits touching `file` on the path from `since`/root to HEAD,
// NEWEST-FIRST (the reverse of git-evidence.js's candidateCommitsForFile,
// which is oldest-first — this resolver needs to walk backward from the
// present).
function candidateCommitsNewestFirst(scanRoot, file, since) {
  const args = ['log', '--format=%H', '--follow'];
  if (since) args.push(`${since}..HEAD`);
  args.push('--', file);
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}

export async function resolveMissingControl(scanRoot, { file, predicate, since, deadlineAt } = {}) {
  if (!file || typeof predicate !== 'function') {
    return { status: 'unknown', commitsConsidered: 0 };
  }
  const candidates = candidateCommitsNewestFirst(scanRoot, file, since);
  if (candidates.length === 0) return { status: 'unknown', commitsConsidered: 0 };

  let commitsConsidered = 0;
  let priorPresentCommit = null; // the most-recently-checked commit where the control WAS present (walking backward, so this is the newest such commit seen so far)

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    let presentHere;
    try { presentHere = await predicate(scanRoot, sha, file); } catch { presentHere = false; }

    if (presentHere) {
      // Found a commit where it WAS present. If we've already seen a LATER
      // (newer) commit where it was NOT present, that later commit's own
      // transition (or the commit just after this one, going forward) is
      // the removal — but walking newest-first, the removal transition is
      // between THIS commit (present) and the previous iteration's commit
      // (absent, checked earlier in this loop = newer in time). So: if
      // priorPresentCommit is unset AND we've already walked past at least
      // one absent commit, that means HEAD-side history is absent and THIS
      // commit is present — the transition is between this commit and the
      // one checked immediately before it in the loop.
      if (commitsConsidered > 1 && priorPresentCommit === null) {
        // The immediately-prior (newer) candidate was absent, and this one
        // is present — that prior candidate (or the gap right after this
        // commit) is where it disappeared. Report THIS commit (the last
        // proven-present one) as the evidence anchor, and the prior
        // candidate as the removal point.
        const removedMeta = commitMeta(scanRoot, candidates[commitsConsidered - 2]);
        const presentMeta = commitMeta(scanRoot, sha);
        if (removedMeta && presentMeta) {
          return {
            status: 'complete',
            removedAt: { commit: removedMeta.commit, authorName: removedMeta.authorName, authorDate: removedMeta.authorDate, summary: removedMeta.summary },
            presentAt: { commit: presentMeta.commit, authorDate: presentMeta.authorDate },
            commitsConsidered,
          };
        }
      }
      priorPresentCommit = sha;
      // Present at the oldest commit we've checked so far and no removal
      // found yet — keep walking older history in case there's an EARLIER
      // removal-then-readd cycle; but for M3's scope (the Scenario I
      // acceptance case is "never present, resolves unknown" and "present
      // then removed, resolves complete"), stop here: control is present
      // at this point in history and we have not yet found where it was
      // removed relative to HEAD. Continue the loop.
    }
    // presentHere === false: keep walking older history (newest-first),
    // looking for the presence that precedes this absence.
  }

  // Walked every candidate and never found a present→absent transition —
  // either the control was NEVER present in any reachable commit (the
  // Scenario I case — must resolve 'unknown', never attributed to the
  // oldest candidate as if that were meaningful), or it has been present
  // at every commit checked (no removal to report, which for THIS
  // resolver's question — "when did it disappear" — is also 'unknown':
  // there is no disappearance to date).
  return { status: 'unknown', commitsConsidered };
}
```

- [ ] **Step 2: Write tests, including Scenario I**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveMissingControl } from '../../src/posture/provenance/missing-control-resolver.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const containsRateLimit = async (scanRoot, sha, file) => {
  const { execFileSync } = await import('node:child_process');
  try {
    const blob = execFileSync('git', ['show', `${sha}:${file}`], { cwd: scanRoot, encoding: 'utf8' });
    return blob.includes('rateLimit(');
  } catch { return false; }
};

test('resolveMissingControl: a control present then removed resolves complete, naming both commits', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');
  fx.writeFile('routes.js', 'app.post("/x", handler);\n');
  const removed = fx.commit('remove rate limiting (regression)');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'complete');
  assert.equal(result.removedAt.commit, removed);
});

test('resolveMissingControl (Scenario I): a control never present in any reachable commit resolves unknown, NEVER attributed to the root commit', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", handler);\n');
  fx.commit('root — no rate limit, never had one');
  fx.writeFile('routes.js', 'app.post("/x", handler); // still no rate limit\n');
  fx.commit('later change, still no rate limit');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'unknown');
  assert.equal(result.removedAt, undefined, 'must never fabricate a removal event for a control that was never present');
});

test('resolveMissingControl: a control present at every checked commit (no removal yet) resolves unknown, not a false "still safe" complete', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler); // still here\n');
  fx.commit('unrelated touch, rate limit still present');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'unknown');
});

test('resolveMissingControl: no file/predicate resolves unknown without throwing', async () => {
  const result1 = await resolveMissingControl('/tmp', {});
  assert.equal(result1.status, 'unknown');
  const result2 = await resolveMissingControl('/tmp', { file: 'x.js' });
  assert.equal(result2.status, 'unknown');
});

test('resolveMissingControl: a predicate that throws is treated as "absent", never crashes the walk', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'x');
  fx.commit('a commit');
  const throwingPredicate = async () => { throw new Error('detector crashed'); };
  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: throwingPredicate });
  assert.equal(result.status, 'unknown');
});

test('resolveMissingControl: respects deadlineAt, reporting budget_exhausted rather than hanging', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'x');
  fx.commit('c1');
  fx.writeFile('routes.js', 'y');
  fx.commit('c2');
  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit, deadlineAt: Date.now() - 1 });
  assert.equal(result.status, 'budget_exhausted');
});
```

- [ ] **Step 3: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-missing-control-resolver.test.js` (foreground, timeout 60000). Expected: PASS, 6/6.

- [ ] **Step 4: Self-review the present→absent transition logic**

The implementer must trace the loop logic in Step 1 by hand against the `'a control present then removed'` test case BEFORE considering this task done — the newest-first walk with a `priorPresentCommit`-tracking approach is subtle. Confirm: with candidates `[removed_commit, added_commit]` (newest-first: `removed_commit` is HEAD-side), iteration 1 (`sha = removed_commit`) finds `presentHere = false` (rate limit was removed here), so the `if (presentHere)` branch is skipped and the loop continues. Iteration 2 (`sha = added_commit`) finds `presentHere = true`; `commitsConsidered = 2 > 1` and `priorPresentCommit === null` (never set), so it enters the transition-found branch, computing `removedMeta` from `candidates[commitsConsidered - 2] = candidates[0] = removed_commit` — correct. If this hand-trace doesn't match, the loop has a bug — fix it before moving on, and add a regression test for whatever the actual bug was.

- [ ] **Step 5: Add to `test:posture` and commit**

Insert into `scanner/package.json`'s `"test:posture"` script.

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/missing-control-resolver.js scanner/test/posture/provenance-missing-control-resolver.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): missing-control regression resolver (M3 §3.3)

resolveMissingControl answers "when did a previously-present safeguard
disappear" — the architectural inverse of every other resolver in this
milestone. A control absent at every reachable commit resolves 'unknown',
never falsely attributed to the root commit (Scenario I). Detector-agnostic
via a caller-supplied predicate. Standalone library module — no existing
detector/finding type in this codebase represents "missing control" yet, so
there is no live caller to wire this into.
EOF
)"
```

---

### Task 11: `schema.js` — close the `AGE_BASIS`/`isProvenanceHealthy` stale TODO

**Files:**
- Modify: `scanner/src/posture/provenance/schema.js`
- Modify: `scanner/src/posture/mttr.js`, `scanner/src/posture/fix-history.js`, `scanner/src/pipeline/assurance-mode.js`, `scanner/bin/agentic-security.js` (each switches ONE existing inline literal to the new shared constant/helper — no behavior change)
- Test: existing test files for each (verify no regression)

**Why now:** M2's final whole-branch review (recommendation #4) found the `AGE_BASIS` enum comment in `schema.js` promising it would be "re-added in the phase that wires age/SLA basis into mttr.js, together with its consumer" — that phase happened in M2, and the enum was not re-added. Since then, the exact same `['complete', 'uncommitted']` healthy-status check now exists independently in THREE places (`bin/agentic-security.js`'s `--require-provenance` block, `assurance-mode.js`'s strict check, and this task adds a fourth consumer's worth of duplication risk if left alone). This is a small, low-risk cleanup task, not a new resolver.

- [ ] **Step 1: Add the enum and helper to `schema.js`**

Current:

```js
// NOTE: an AGE_BASIS enum (finding_origin | earliest_observable |
// first_observed | uncommitted) was specified here and is deliberately NOT
// exported yet — nothing in M0+M1 computes an age, so it was dead the moment
// it shipped and `no-dead-modules.test.js` said so. Re-add it in the phase that
// wires age/SLA basis into mttr.js, together with its consumer.
```

becomes:

```js
// M3: the AGE_BASIS enum, re-added now that M2 shipped its two consumers
// (mttr.js's ageBasis field, fix-history.js's provenanceAtFix.ageBasis) —
// both previously used bare string literals matching this vocabulary
// without importing a shared source of truth for it.
export const AGE_BASIS = Object.freeze({
  FINDING_ORIGIN: 'finding_origin',
  EARLIEST_OBSERVABLE: 'earliest_observable',
  FIRST_OBSERVED: 'first_observed',
  UNCOMMITTED: 'uncommitted',
});

// The `['complete', 'uncommitted']` "provenance is healthy enough to trust"
// check independently exists in THREE places today (bin/agentic-security.js's
// --require-provenance block, pipeline/assurance-mode.js's strict check, and
// mttr.js's/fix-history.js's own ageBasis tiering all re-derive the same
// status set locally). One shared predicate, so a future change to what
// counts as "healthy" is a one-line edit, not a grep-and-fix-N-places.
export function isProvenanceHealthy(findingProvenance) {
  return ['complete', 'uncommitted'].includes(findingProvenance?.status);
}
```

- [ ] **Step 2: Switch `mttr.js` to the shared enum**

In `scanner/src/posture/mttr.js`, add the import and switch the four string literals to the enum members. Current (from M2's Task 6):

```js
    if (status === 'complete' && origin?.authorDate) {
      f.ageBasis = 'finding_origin';
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'partial' && origin?.authorDate) {
      f.ageBasis = 'earliest_observable';
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'uncommitted') {
      f.ageBasis = 'uncommitted';
      f.provenAgeDays = f.ageDays;
    } else {
      f.ageBasis = 'first_observed';
      f.provenAgeDays = f.ageDays;
    }
```

becomes:

```js
    if (status === 'complete' && origin?.authorDate) {
      f.ageBasis = AGE_BASIS.FINDING_ORIGIN;
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'partial' && origin?.authorDate) {
      f.ageBasis = AGE_BASIS.EARLIEST_OBSERVABLE;
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'uncommitted') {
      f.ageBasis = AGE_BASIS.UNCOMMITTED;
      f.provenAgeDays = f.ageDays;
    } else {
      f.ageBasis = AGE_BASIS.FIRST_OBSERVED;
      f.provenAgeDays = f.ageDays;
    }
```

Add `import { AGE_BASIS } from './provenance/schema.js';` to `mttr.js`'s existing import block (check exact current imports first — the file currently imports only `node:crypto`).

- [ ] **Step 3: Switch `fix-history.js` to the shared enum**

Same mechanical substitution in `_snapshotProvenanceAtFix` (from M2's Task 5) — the four string literals `'finding_origin'`/`'earliest_observable'`/`'uncommitted'`/`'first_observed'` become `AGE_BASIS.FINDING_ORIGIN`/`AGE_BASIS.EARLIEST_OBSERVABLE`/`AGE_BASIS.UNCOMMITTED`/`AGE_BASIS.FIRST_OBSERVED`. Add the import.

- [ ] **Step 4: Switch `assurance-mode.js` and `bin/agentic-security.js` to `isProvenanceHealthy`**

In `scanner/src/pipeline/assurance-mode.js`, the current:

```js
  const badProvenance = (Array.isArray(findings) ? findings : []).filter((f) => {
    const s = f?.findingProvenance?.status;
    return !['complete', 'uncommitted'].includes(s);
  });
```

becomes:

```js
  const badProvenance = (Array.isArray(findings) ? findings : []).filter((f) => !isProvenanceHealthy(f?.findingProvenance));
```

Add `import { isProvenanceHealthy } from '../posture/provenance/schema.js';` to this file's existing imports.

In `scanner/bin/agentic-security.js`, the `--require-provenance` block's current:

```js
        if (['complete', 'uncommitted'].includes(f.findingProvenance?.status)) continue;
```

becomes:

```js
        if (isProvenanceHealthy(f.findingProvenance)) continue;
```

Add `isProvenanceHealthy` to whatever dynamic/static import already brings in provenance schema constants in this file (check its existing import pattern for `emptyProvenance`/`PROVENANCE_STATUS` if any, or add a new import line matching the file's existing style for importing from `src/posture/provenance/schema.js`).

- [ ] **Step 5: Run the affected test scopes**

Run: `cd scanner && node --test test/mttr.test.js test/fix-history.test.js test/assurance-mode.test.js` (foreground, timeout 120000). Expected: PASS, no behavior change (these are pure literal-to-constant substitutions).

Run: `cd scanner && npm run build 2>&1 | tail -20` (you touched `bin/agentic-security.js` and multiple `src/` files).

Run: `cd scanner && node --test test/ci.test.js` (foreground, timeout 120000) — exercises `--require-provenance` and `--assurance strict` through the real bundled CLI. Expected: PASS.

- [ ] **Step 6: Run `no-dead-modules.test.js` explicitly**

The ORIGINAL reason `AGE_BASIS` was withheld was `no-dead-modules.test.js` flagging it as unused. Run: `cd scanner && node --test test/no-dead-modules.test.js` (foreground, timeout 60000) to confirm the now-real usage satisfies that check. Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/schema.js scanner/src/posture/mttr.js scanner/src/posture/fix-history.js scanner/src/pipeline/assurance-mode.js scanner/bin/agentic-security.js scanner/dist/
git commit -m "$(cat <<'EOF'
refactor(provenance): close the AGE_BASIS/isProvenanceHealthy stale TODO (M2 review rec #4)

schema.js's AGE_BASIS enum (withheld since M0+M1 as dead code) is re-added
now that M2 shipped two real consumers. isProvenanceHealthy() replaces
three independent copies of the same ['complete','uncommitted'] check
(bin/agentic-security.js, assurance-mode.js) with one shared predicate.
Pure substitution — no behavior change, verified via the existing test
suites for every touched file.
EOF
)"
```

---

## End-of-plan: final build + whole-branch verification

After Task 11 (the last task), before the final whole-branch review:

- [ ] Run `cd scanner && npm run build 2>&1 | tail -20` (foreground, timeout 120000) and confirm it completes without error.
- [ ] Run `cd scanner && npm test` (foreground, timeout 700000 — the full CI gate takes ~10-12 minutes) and capture the REAL exit code, not a piped `tail`'s. Compare failures against the known pre-existing flaky test list already established this session (subprocess-spawn timeout signature, `status: null`, in `plugin-self-check.test.js`/`posture-command.test.js`/`labs-command.test.js`/`compliance-command.test.js`/`policy-bundle.test.js`) — a NEW failure outside that list is a real regression requiring investigation, not something to wave away.
- [ ] Run `cd scanner && npm run bench:cve-replay:check` (foreground, timeout 300000) and `npm run bench:self-scan:check` (foreground, timeout 300000, wiping stray `.agentic-security` dirs under `bench/self-scan` first per this repo's own documented discipline) — both must pass.
- [ ] Run `cd scanner && npm run bench:provenance:check` (foreground, timeout 300000) — M3 added real resolution work to the transitive-SCA and deep-mode paths; confirm the M2-established overhead baseline hasn't regressed materially. If it has, re-baseline deliberately with `npm run bench:provenance:update-baseline` and say why in the commit — never silently accept a worse number without comment.
