# Finding Provenance PRD Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 10 confirmed gaps between the source Finding Provenance PRD (`Agentic-Security-Finding-Provenance-PRD.docx`) and what M0-M4 actually shipped, found by an independent audit against the PRD's own literal wording (not the design spec's paraphrase of it).

**Architecture:** Eleven independent-to-mostly-independent additions layered on the existing M0-M4 provenance pipeline (`scanner/src/posture/provenance/`). None change the terminal-status/never-false-certainty/one-budget invariants — most either extend an existing resolver to a new caller, add a missing field to an existing shape, or add a genuinely new, narrowly-scoped capability (pseudonymization, an accuracy corpus).

**Tech Stack:** Node.js ESM, `node:crypto` (pseudonymization hash, matches Ed25519 key material already in use), `node:child_process` (via `git-evidence.js`'s existing wrapper only).

**Source of truth:** The PRD itself (`Agentic-Security-Finding-Provenance-PRD.docx`, extracted via `textutil -convert txt -stdout`). Where this plan cites "PRD §N" it means that document's own section numbers, not the design spec's.

## Global Constraints

(Inherited verbatim from M2-M4's own established constraints — every task implicitly includes these:)
- Terminal status always present, never left `undefined`.
- Never false certainty (a resolver that can't prove absence reports `partial`/`unknown`/`not_available`, never guesses).
- Read-only Git access only; no new module runs `checkout`/`merge`/hooks.
- No new module persists raw secret/blob content anywhere.
- No new npm dependency without a documented reason.
- Deterministic output for a fixed HEAD.
- No runtime network call without an explicit, documented opt-in and offline-degrades-gracefully test.
- ESM throughout. All git access routes through `git-evidence.js` — no new module reimplements its own git wrapper (this exact mistake has been caught and fixed twice already in this project's history — M3's `missing-control-resolver.js` and — no, corrected — it was found in that module's initial draft before ever shipping, and independently in M4's `repo-lineage.js` initial draft; both were fixed before merge. Do not re-introduce it a third time).
- `annotateGitProvenance` is the ONLY function name for the main coordinator entry point.
- **New for this plan**: every task that changes the fixed/synthetic finding classification, the stableId backfill logic, or the annotator pipeline must NOT regress `bench/cve-replay/check` or `bench/self-scan/check` — these gates exist precisely to catch a detection-shape change no unit test anticipated.

## Global Research Findings (binding on every task that touches them — do not re-derive, verify against current source instead)

These were established by dedicated research passes before this plan was written. Each task below cites the specific finding it depends on; this section is the canonical record in case source has drifted since.

- **Task 10 (FR-029) root cause**: `predicate-replay.js`'s `replayAt` calls `runFullScan(..., {provenance:false})`, which runs the FULL ~54-annotator pipeline unconditionally, even though `replayAt` only ever reads `scan.findings`/`scan.secrets` to call `computeStableId` — none of the 54 annotators' output is used. Measured cost: ~39ms/call fixed overhead regardless of file size, dominating the ~30x bench overhead. M3/M4's own additions (deep mode, transitive SCA, cross-repo lineage, AI-authorship) are NOT implicated — the bench fixture never exercises them.
- **Task 11 (secrets/logicVulns) critical trap**: `predicate-replay.js`'s `replayAt` candidate pool is `[...scan.findings, ...scan.secrets]` — `scan.secrets` is ALREADY included; `scan.logicVulns` is NOT. Wiring `logicVulns` into `annotateGitProvenance` without also fixing this line would make every logicVulns finding silently and permanently resolve `status:'partial', reason:'predicate-never-confirmed-in-candidates'` — a plausible-looking but wrong result. This fix must land in the SAME commit as (or before) the logicVulns wiring, never after.
- **Task 11 scope correction**: `scan.logicVulns` is not one detector's output — it's ~9 distinct producers. Three of them (`license-policy:`, `deploy-platform:`, `stack-playbook:` — identifiable by `id` prefix) use a fixed placeholder `line` (0 or 1) that is NOT a real diffable source location; running these through git-blame-style resolution would fabricate a plausible-looking but meaningless origin (e.g. "package.json line 1 was introduced in whatever commit last touched that line"). These three must be excluded and kept on an honest, permanent `not_available` with an accurate limitation string — never routed through `resolveOrigin`.
- **Task 9 (FR-022) budget concern**: `fetchPRMetadata`/`fetchCodeowners` each have an 8s `AbortSignal.timeout`, but nothing bounds the AGGREGATE time across N findings in one scan — a scan with 100 complete-status findings and a configured provider could attempt up to 800s of sequential calls, violating "one budget for the whole scan." Fix: cap the number of findings enriched per scan (not per-call timeout tuning), and disclose the cap per this codebase's "no silent caps" convention.
- **Task 5 (retention) scope correction**: the obvious fix (add a `retentionClass` to the existing `provenance` artifact-registry entry) DOES NOT WORK — `cmdReset`/`findExpiredArtifacts` operate on TOP-LEVEL `.agentic-security/` directory names only (exact string match, no entry has ever had a `/` in its name). The cache (`provenance/cache/*.json`) and the lifecycle ledger (`provenance/lifecycle.json`) are nested under one shared top-level `provenance/` directory today, so they cannot get different retention treatment without a real physical storage-location change: moving the cache to its own top-level directory (e.g. `provenance-cache/`).

## Pre-flight cross-task conflict notes

- **Task 10 and Task 11 both touch `engine.js`'s provenance block** (~lines 10170-10373) and **both touch `predicate-replay.js`** (Task 10 adds a `skipAnnotators` option used by `replayAt`; Task 11 adds `scan.logicVulns` to `replayAt`'s candidate pool). Dispatch Task 10 before Task 11 — Task 11's implementer must re-read `predicate-replay.js` and `engine.js`'s provenance block fresh after Task 10 lands, not from this plan's own line-number citations (which will have shifted).
- **Task 8 (FR-017) and Task 11 both extend `coordinator.js`'s `isSca`/`isTransitiveSca` branch pattern** — Task 8 adds a fourth `isMissingControl`-style branch; Task 11 explicitly does NOT need a new branch (confirmed by research: secrets/logicVulns fall through to the plain SAST path with no `findingType` needed). Dispatch order between 8 and 11 doesn't matter for correctness, but Task 11's implementer should read whatever `coordinator.js` looks like after Task 8, in case Task 8's new branch changed the shape of the fall-through `else` path.
- **Task 4 (pseudonymization) and Task 1 (terminal sanitization) both touch `report/index.js`'s `_normalizedProvenance`/CLI rendering path** — different concerns (privacy vs. safety), should compose cleanly, but Task 4's implementer should re-read whatever Task 1 shipped there.
- **Task 6 (coverage metric) depends on Task 11 being informative but not blocking** — the coverage metric will legitimately read LOW for secrets until Task 11 ships; this is correct, not a bug, and Task 6's own text should say so. Dispatch order doesn't matter; sequence Task 6 after Task 11 anyway so its own manual verification step shows a more interesting (non-zero) secrets coverage number.
- **Task 9 (FR-022) depends on Task 11 NOT AT ALL** — provider enrichment only fires on `status:'complete'` SAST-shaped origins, unrelated to secrets/logicVulns wiring.

---

### Task 1: FR-PROV-026 — sanitize author name / commit summary against terminal and markup injection

**Files:**
- Modify: `scanner/src/report/index.js` (`explainProvenance`, and any other CLI-text renderer touching `findingOrigin.authorName`/`.summary` or `branchIntroduction`)
- Test: `scanner/test/security/provenance-injection.test.js` (new)

**Interfaces:**
- Produces: `sanitizeForTerminal(str)` — a new exported helper (co-locate in `report/index.js` near `explainProvenance`, or in `schema.js` if that fits this codebase's convention better — check where similar sanitization helpers already live in this codebase, e.g. search for how `secret-safe` redaction or existing terminal-color helpers strip/escape untrusted text, and match that pattern rather than inventing a new one).

- [ ] **Step 1: Confirm the exact vulnerable call site and existing conventions**

Read `scanner/src/report/index.js`'s `explainProvenance` function in full (confirmed this session at line 107). Confirm line 115's exact current text: `` `Introduced:      ${short(o.commit)}  •  ${day(o.authorDate)}  •  ${o.authorName || 'unknown'}` ``. Also grep the whole file for every OTHER place `authorName`, `findingOrigin.summary`, `branchIntroduction.relationship`, or any other free-text field sourced from git metadata gets embedded into a template string destined for `console.log`/CLI/Markdown output — this task must close ALL of them, not just line 115. Also check `toCLI`/`toSummary` for any additional call sites.

Search this codebase for any EXISTING sanitization utility before writing a new one — check `posture/secret-history.js` or wherever secret redaction happens for a "strip control characters" helper that might already exist and just needs reuse. If nothing exists, write a new minimal one.

- [ ] **Step 2: Write the sanitizer**

```js
// Untrusted commit metadata (author name, commit summary) must never reach
// a terminal or a Markdown/HTML renderer un-sanitized — PRD FR-PROV-026.
// Strips ANSI/control escape sequences (a malicious author name containing
// \x1b[2J or similar could manipulate terminal state) and collapses
// newlines (a multi-line "author name" could forge extra output lines).
// This is layered UNDER the existing HTML-escaping path (which already
// protects the HTML renderer via JSON-escaping before embedding) — this
// helper is specifically for the CLI/terminal text path, which had none.
export function sanitizeForTerminal(str) {
  if (typeof str !== 'string') return str;
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').replace(/[\r\n]+/g, ' ').trim();
}
```

**Verify this regex is correct before shipping**: it must strip C0 control characters (0x00-0x1F) EXCEPT tab (0x09) and the newline/CR characters, which are separately collapsed to a space rather than stripped (so a multi-line injection doesn't just vanish silently, leaving suspicious blank space — it becomes a single visible line instead, which is both safer AND more honest about what was in the data). It must also strip DEL (0x7F). Confirm `\x1b` (ESC, the ANSI escape lead byte) is covered by the `\x0E-\x1F` range (yes: 0x1B is within 0x0E-0x1F). Write a quick throwaway test with a real ANSI escape sequence (`\x1b[2J\x1b[H`) and confirm it's fully stripped before moving on.

- [ ] **Step 3: Apply it at every call site found in Step 1**

At minimum, `explainProvenance`'s line 115 becomes:
```js
    lines.push(`Introduced:      ${short(o.commit)}  •  ${day(o.authorDate)}  •  ${sanitizeForTerminal(o.authorName) || 'unknown'}`);
```
Apply the same wrapping to `o.summary` (if rendered anywhere in this function or elsewhere) and to `branchIntroduction.relationship` (lower risk since it's an enum value we control, but the PRD names "commit messages" explicitly — if `summary` is rendered anywhere, it must be wrapped).

Also check the Markdown renderer (`toMarkdown` or equivalent) — Markdown injection (a commit message containing `](javascript:...)` or similar) is a DIFFERENT risk than terminal injection; confirm whether Markdown output already escapes `[`/`]`/backticks from untrusted text, and if not, apply a Markdown-specific escape there too (do not just reuse `sanitizeForTerminal` for Markdown — different escaping rules apply. If this is out of scope after investigation because Markdown output already handles it via some other existing mechanism, confirm this explicitly in your report rather than silently skipping it).

- [ ] **Step 4: Write the injection fixture tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainProvenance, sanitizeForTerminal } from '../../src/report/index.js';

test('sanitizeForTerminal: strips ANSI escape sequences', () => {
  const malicious = 'Evil\x1b[2J\x1b[HName';
  const clean = sanitizeForTerminal(malicious);
  assert.ok(!clean.includes('\x1b'), 'ESC byte must be stripped');
});

test('sanitizeForTerminal: collapses embedded newlines to a single line', () => {
  const malicious = 'Real Name\nFAKE: Introduced: abc123 by Nobody';
  const clean = sanitizeForTerminal(malicious);
  assert.ok(!clean.includes('\n'), 'newline must not survive');
  assert.equal(clean.split('\n').length, 1);
});

test('sanitizeForTerminal: leaves ordinary names untouched', () => {
  assert.equal(sanitizeForTerminal('Jamie Chen'), 'Jamie Chen');
  assert.equal(sanitizeForTerminal("O'Brien-Smith"), "O'Brien-Smith");
});

test('explainProvenance: a malicious authorName in a real finding never reaches raw output with control characters', () => {
  const f = {
    findingProvenance: {
      status: 'complete',
      findingOrigin: {
        commit: 'abc1234567890', authorDate: '2026-01-01T00:00:00Z',
        authorName: 'Evil\x1b[2J\x1b[HPwned', summary: 'x',
      },
      method: 'semantic-history-replay',
      confidence: { level: 'high', score: 0.9, reasons: [] },
    },
  };
  const rendered = explainProvenance(f);
  assert.ok(rendered && rendered.length > 0);
  for (const line of rendered) {
    assert.ok(!/\x1b/.test(line), `line contains raw ESC: ${JSON.stringify(line)}`);
  }
});
```

**Fix the exact `explainProvenance` return shape assumption in the last test** — check whether it returns an array of lines, a joined string, or something else (this plan's earlier reading suggests an array called `lines`, but confirm the actual `return` statement before finalizing this test).

- [ ] **Step 5: Run and verify**

Run: `cd scanner && node --test test/security/provenance-injection.test.js test/report/provenance-output.test.js` (foreground, timeout 60000) — the second file is the existing golden-output test suite; re-running it confirms this change didn't alter any EXISTING non-malicious rendering (a sanitizer that's too aggressive would break normal author names with legitimate punctuation).

- [ ] **Step 6: Add to test scope and commit**

Insert into `scanner/package.json`'s appropriate scoped test script (check whether `test:report` or `test:posture` covers `test/report/*.test.js` and `test/security/*.test.js` respectively, and place the new file in the matching one).

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/report/index.js scanner/test/security/provenance-injection.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
fix(provenance): sanitize author name / commit text against terminal injection (FR-PROV-026)

PRD audit found report/index.js's CLI text renderer embedded
findingOrigin.authorName raw into console output with zero sanitization
-- a malicious commit author name could inject ANSI control sequences.
HTML output was already safe (JSON-escaped before embedding); the CLI
text path was not. sanitizeForTerminal() strips control characters and
collapses embedded newlines.
EOF
)"
```

---

### Task 2: Evidence digest — bind the 5 PRD-named inputs `computeDigest` currently omits

**Files:**
- Modify: `scanner/src/posture/provenance/coordinator.js` (`computeDigest`)
- Test: extend `scanner/test/posture/provenance-coordinator.test.js`

**Interfaces:**
- Consumes: nothing new.
- Produces: `computeDigest`'s material gains 4 new bound fields (blob IDs are addressed separately below — see the scope note).

- [ ] **Step 1: Read the PRD's exact "Evidence integrity" requirement and the current implementation side by side**

PRD (Data Contract section, "Evidence integrity" paragraph): "The evidence digest must bind the stable finding ID, repository identity, analysis HEAD, origin commit, branch-introduction commit, evidence-node locations and blob IDs, detector/ruleset version, history boundary, method, confidence reasons, and limitations."

Current `computeDigest` (confirmed this session, `coordinator.js:86-97`):
```js
function computeDigest(finding, provenance) {
  const material = JSON.stringify({
    stableId: finding.stableId,
    origin: provenance.findingOrigin?.commit || null,
    branchEntry: provenance.branchIntroduction?.commit || null,
    evidence: (provenance.evidenceAttribution || []).map((n) => `${n.role}:${n.path}:${n.line}:${n.commit}`),
    method: provenance.method,
    reasons: provenance.confidence?.reasons || [],
    limitations: provenance.limitations,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}
```

Missing per the PRD: repository identity, analysis HEAD, detector/ruleset version, history boundary. (Blob IDs are handled separately — see Step 3's scope note; do not attempt to add them without reading that note first.)

- [ ] **Step 2: Add the 4 missing fields**

`provenance.analysisBasis` already carries `head`, `ruleset`, `detector` (confirmed in `schema.js`'s `emptyProvenance`). `provenance.historyCoverage.boundaryCommit` already exists as a field (though this session's audit found it's currently ALWAYS `null` — that's a separate, not-in-scope-for-this-plan gap; binding a field that happens to always be `null` today is still correct and future-proofs the digest for whenever `boundaryCommit` gets populated).

"Repository identity" needs a source — check whether `coordinator.js`'s `annotateGitProvenance` or `git-evidence.js`'s `getRepoState` already computes anything identity-like (a remote URL, if Task 9/FR-022's `getRemoteUrl` helper landed first — check for it; if this task is dispatched before Task 9, `getRemoteUrl` won't exist yet, so use `scanRoot` itself — the absolute path — as a best-effort repository identity value instead, with a comment noting a remote-URL-based identity is a stronger future signal once Task 9's `getRemoteUrl` exists).

```js
function computeDigest(finding, provenance, repoIdentity) {
  const material = JSON.stringify({
    stableId: finding.stableId,
    repoIdentity: repoIdentity || null,
    analysisHead: provenance.analysisBasis?.head || null,
    origin: provenance.findingOrigin?.commit || null,
    branchEntry: provenance.branchIntroduction?.commit || null,
    evidence: (provenance.evidenceAttribution || []).map((n) => `${n.role}:${n.path}:${n.line}:${n.commit}`),
    detectorVersion: provenance.analysisBasis?.detector || null,
    rulesetVersion: provenance.analysisBasis?.ruleset || null,
    historyBoundary: provenance.historyCoverage?.boundaryCommit || null,
    method: provenance.method,
    reasons: provenance.confidence?.reasons || [],
    limitations: provenance.limitations,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}
```

Find `computeDigest`'s call site (`provenance.evidenceDigest = computeDigest(finding, provenance);`, confirmed this session at coordinator.js:335) and thread a `repoIdentity` argument through — trace where `scanRoot` is already available at that call site and pass it directly as the best-effort identity value: `computeDigest(finding, provenance, scanRoot)`.

**This is a breaking change to the digest's VALUE** (not shape) — every previously-computed digest will now differ from a freshly-recomputed one for the same finding, since the hashed material changed. Confirm this is acceptable: check whether any EXISTING test hardcodes a specific digest STRING (as opposed to just checking two computations match or checking tamper-detection) — if so, that test's expected value needs updating, which is expected and fine, not a sign of a bug.

- [ ] **Step 3: Scope note — evidence-node blob IDs are explicitly OUT OF SCOPE for this task**

The PRD also names "evidence-node locations and blob IDs" — locations (path:line:commit) are already bound; blob IDs (a `git hash-object`-style content hash per evidence node) are NOT computed ANYWHERE upstream in the pipeline today (confirmed this session: `getBlobAtCommit` returns raw text content, never a blob SHA; no caller runs `git hash-object` or reads a tree entry's OID). Adding this would require a real new git-evidence.js primitive and touching every evidence-node construction site across `origin-resolver.js`, `sca-origin.js`, `transitive-sca.js`, and `evidence-attribution.js` — a materially larger task than this one's scope. Do NOT attempt to add blob IDs in this task. Document this explicitly as a known, deliberate limitation in `computeDigest`'s own header comment (add one if none exists) so a future reader understands this is a scoped, not accidental, omission.

- [ ] **Step 4: Write tests**

```js
// Add to provenance-coordinator.test.js:

test('computeDigest: repository identity and analysis HEAD are now bound (PRD Evidence integrity)', async () => {
  // Build two findings identical in every digest-relevant field EXCEPT
  // scanRoot (repository identity) or analysisBasis.head, and confirm
  // their digests differ -- this is the actual security property: two
  // different repos or two different HEADs must never produce the same
  // digest for "the same" stableId/origin/branch/evidence tuple.
  // (Fill in with real fixtures matching this file's existing conventions
  // for constructing a finding + provenance object -- read a few existing
  // tests in this file first to match the established pattern rather than
  // inventing a new fixture shape.)
});

test('computeDigest: detector/ruleset version changes the digest', async () => {
  // Same technique: two provenance objects identical except
  // analysisBasis.detector or analysisBasis.ruleset differ; digests must differ.
});
```

**These two test bodies are intentionally under-specified** — fill them in against this test file's REAL existing fixture-construction pattern (read at least 2 existing tests in `provenance-coordinator.test.js` first) rather than guessing at a shape.

- [ ] **Step 5: Run, verify, and check for a hardcoded-digest-string regression**

Run: `cd scanner && node --test test/posture/provenance-coordinator.test.js` (foreground, timeout 60000). If any pre-existing test fails because it hardcoded a specific digest string, update that expected value (do NOT loosen the assertion to "any string" — the whole point of a digest test is pinning specific input-to-output behavior; recompute the new expected value from the actual code and hardcode the new one).

Run: `cd scanner && npm run test:posture` (foreground, timeout 300000) — broad regression check since `computeDigest`'s signature changed and every caller needs to still compile/pass its own arguments correctly.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/coordinator.js scanner/test/posture/provenance-coordinator.test.js
git commit -m "$(cat <<'EOF'
fix(provenance): bind repo identity, analysis HEAD, detector/ruleset version, history boundary into the evidence digest

PRD audit found computeDigest omitted 4 of the 11 inputs the PRD's own
"Evidence integrity" paragraph names -- a digest collision was possible
across two different repos, two different HEADs, or two different
ruleset versions sharing the same stableId/origin/branch/evidence tuple.
Evidence-node blob IDs (the 5th named-but-missing input) are explicitly
scoped OUT -- no blob-hashing primitive exists anywhere upstream yet;
documented as a deliberate limitation, not an oversight.
EOF
)"
```

---

### Task 3: symlink-escape protection for the provenance pipeline

**Files:**
- Modify: `scanner/src/posture/provenance/git-evidence.js` (`_relPath`)
- Test: extend `scanner/test/posture/provenance-git-evidence.test.js`

**Interfaces:**
- Consumes: nothing new.
- Produces: `_relPath` gains a real symlink check (currently purely lexical).

- [ ] **Step 1: Confirm the current gap**

Read `git-evidence.js`'s `_relPath` function in full (confirmed this session, lines 26-30 roughly):
```js
function _relPath(scanRoot, file) {
  const abs = path.resolve(scanRoot, file);
  const rel = path.relative(scanRoot, abs);
  return (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) ? null : rel.split(path.sep).join('/');
}
```
This is PURELY LEXICAL — it rejects `../foo` and absolute paths, but a `file` argument that lexically resolves INSIDE `scanRoot` while being a SYMLINK whose target is OUTSIDE `scanRoot` would pass this check and then get handed to a `git show`/`git log` call, potentially reading content outside the intended tree via the symlink. Confirm there is genuinely no `fs.realpathSync`/`fs.lstatSync` anywhere in this file or elsewhere in `provenance/` (grep for "realpath"/"symlink"/"lstat" in the whole directory — this session's audit found zero hits; re-confirm).

- [ ] **Step 2: Add a real symlink check**

```js
import * as fs from 'node:fs';

function _relPath(scanRoot, file) {
  const abs = path.resolve(scanRoot, file);
  const rel = path.relative(scanRoot, abs);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  // Lexical containment alone isn't enough: `file` could be a symlink whose
  // TARGET resolves outside scanRoot even though its own path lexically
  // sits inside it. realpathSync follows every symlink in the chain; if the
  // real (post-symlink) path escapes scanRoot, treat it the same as any
  // other traversal attempt. A file that genuinely doesn't exist at this
  // path/commit isn't this function's problem to diagnose -- realpathSync
  // throwing ENOENT here just means "can't verify, so don't trust it,"
  // matching every other fail-closed check in this module.
  try {
    const real = fs.realpathSync(abs);
    const realRoot = fs.realpathSync(scanRoot);
    const realRel = path.relative(realRoot, real);
    if (realRel === '' || realRel.startsWith('..') || path.isAbsolute(realRel)) return null;
  } catch {
    // Path doesn't exist on disk right now (common and expected -- most
    // callers are asking about a file's state at some HISTORICAL commit,
    // which git-evidence.js reads from git objects, not the working tree;
    // the working tree may not even have this file, or may have it under a
    // different name after a rename). Only reject on a REAL, PROVEN escape,
    // never on "couldn't check" -- that would make every historical query
    // fail closed for the wrong reason.
  }
  return rel.split(path.sep).join('/');
}
```

**Think carefully about the `catch` block before shipping this** — the brief's own reasoning above argues for NOT rejecting on ENOENT, since most provenance queries are about historical commits where the current working-tree file may not exist at all (or may not exist under this exact path due to a rename). Confirm this reasoning is sound by checking a few real call sites of `_relPath` — do they always expect a working-tree-resident file, or do they routinely call this on paths whose current on-disk state is irrelevant (since the actual read happens via `git show <sha>:<path>`, not a direct filesystem read)? If `_relPath`'s callers genuinely never touch the filesystem directly (only use the returned relative path string to build a git command), then a symlink CANNOT do anything dangerous via this specific function's callers today — the real risk would only materialize if some OTHER function reads the resolved path directly off disk. Trace this before finalizing: grep the whole `provenance/` directory for any `fs.readFileSync`/`fs.readdirSync` call that uses `_relPath`'s return value as a literal filesystem path (not as a `git show` argument) — if you find one, that's the actually-exploitable site and the fix belongs there too, not just in `_relPath` alone. Report your finding either way.

- [ ] **Step 3: Write a real symlink-escape test**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createGitFixture } from '../helpers/build-git-fixture.js';

test('git-evidence.js: a symlink inside scanRoot pointing outside it is rejected, not silently followed', () => {
  const fx = createGitFixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-symlink-target-'));
  try {
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside content');
    const linkPath = path.join(fx.root, 'innocent-looking.js');
    fs.symlinkSync(path.join(outside, 'secret.txt'), linkPath);
    fx.commit('add a symlink'); // git tracks the symlink itself, not its target's content

    // Import _relPath -- check whether it's exported; if not, exported ONLY
    // for this test via a test-only export path, matching this codebase's
    // existing convention for testing other internal helpers (check how
    // _isSha/_isSafeRevision were exported in git-evidence.js during M3's
    // fix round, and match that same pattern here).
    const { _relPath } = await import('../../src/posture/provenance/git-evidence.js');
    const result = _relPath(fx.root, 'innocent-looking.js');
    assert.equal(result, null, 'a symlink escaping scanRoot must be rejected');
  } finally {
    fx.cleanup();
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('git-evidence.js: an ordinary file (no symlink) still resolves normally', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('normal.js', 'x');
    fx.commit('c1');
    // (import pattern matching the test above)
    const result = _relPath(fx.root, 'normal.js');
    assert.equal(result, 'normal.js');
  } finally { fx.cleanup(); }
});
```

**Fix the `await import` inside a non-async test callback** — Node's test runner requires the callback itself be `async` for a top-level `await` inside it to work; confirm both test callbacks above are declared `async (t) => {...}` or restructure the import to the top of the file if `_relPath` is a stable export unlikely to need dynamic-import-per-test. Also confirm the EXACT technique for exporting a normally-private helper for testing, matching this file's own established convention (there should be precedent from this session's earlier work on this exact file).

- [ ] **Step 4: Run and verify**

Run: `cd scanner && node --test test/posture/provenance-git-evidence.test.js` (foreground, timeout 60000). Confirm PASS, all existing tests plus the 2 new ones.

Run: `cd scanner && npm run test:posture` (foreground, timeout 300000) — `_relPath` is used throughout the whole provenance pipeline; a broad regression check is warranted for a change to this shared primitive.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/git-evidence.js scanner/test/posture/provenance-git-evidence.test.js
git commit -m "$(cat <<'EOF'
fix(provenance): reject symlink escapes in git-evidence.js's path relativization (PRD Section 8)

_relPath was purely lexical -- it rejected ../ and absolute paths but not
a symlink whose target resolves outside scanRoot while its own path sits
lexically inside it. Added a realpathSync-based check, fail-open only on
ENOENT (a file not existing in the CURRENT working tree is expected and
routine for a query about a HISTORICAL commit -- only a PROVEN escape is
rejected).
EOF
)"
```

---

### Task 4: author-name pseudonymization

**Files:**
- Modify: `scanner/src/posture/provenance/schema.js` (`redactFindingProvenance`)
- Modify: `scanner/bin/agentic-security.js` (new `--pseudonymize-authors` flag)
- Modify: `scanner/src/report/index.js` (`_normalizedProvenance`)
- Test: extend `scanner/test/posture/provenance-schema.test.js` (or wherever `redactFindingProvenance`'s existing tests live — check first) and `scanner/test/cli/provenance-flags.test.js`

**Interfaces:**
- Produces: `pseudonymizeAuthor(authorName, authorEmail)` (schema.js), `redactFindingProvenance(fp, {includeEmail, pseudonymize})`.

- [ ] **Step 1: Confirm the exact existing `--include-author-email` pattern to mirror**

Read `bin/agentic-security.js` at the 4 line numbers found this session (198, 416, 488, 600 — re-confirm exact current numbers, they will have shifted) tracing the FULL chain: flag parsing → `_provFlags.includeEmail` → `process.env.AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL` → read back in `report/index.js`'s `_normalizedProvenance` → passed into `redactFindingProvenance({includeEmail})`. Reproduce this exact chain shape for the new flag, do not invent a different wiring mechanism.

- [ ] **Step 2: Add `pseudonymizeAuthor` to schema.js**

```js
import * as crypto from 'node:crypto';
// (schema.js currently has zero imports -- confirm this is still true; if
// something else added an import since this plan was written, just add
// this one alongside it rather than assuming you're adding the first.)

/**
 * A stable, one-way pseudonym for an author -- PRD Section 8: "support
 * organization policy to pseudonymize names while retaining an internal
 * stable identity reference." Keyed on email when available (more stable
 * across commits than a display name, which can vary in capitalization or
 * formatting across different commits by the same person) with a fallback
 * to name alone. Deterministic: the SAME author always gets the SAME
 * pseudonym within one run (and across runs, since it's a pure function of
 * the input, not randomized) -- this is what "stable identity reference"
 * means: a reader can tell "these five findings share an author" without
 * learning who that author is.
 */
export function pseudonymizeAuthor(authorName, authorEmail) {
  const key = authorEmail || authorName || '';
  if (!key) return 'Contributor-unknown';
  const hash = crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);
  return `Contributor-${hash}`;
}
```

- [ ] **Step 3: Extend `redactFindingProvenance`**

Read the current function (schema.js:70-77 per this session's reading) and extend its options:
```js
export function redactFindingProvenance(fp, { includeEmail = false, pseudonymize = false } = {}) {
  if (!fp) return null;
  const redactOrigin = (origin) => origin
    ? {
        ...origin,
        authorEmail: includeEmail ? origin.authorEmail : null,
        authorName: pseudonymize ? pseudonymizeAuthor(origin.authorName, origin.authorEmail) : origin.authorName,
      }
    : null;
  return {
    ...fp,
    findingOrigin: redactOrigin(fp.findingOrigin),
  };
}
```

**Order of operations matters**: pseudonymization must key on the REAL `authorEmail` (before it gets nulled by the `includeEmail` check) — confirm the code above computes `pseudonymizeAuthor(origin.authorName, origin.authorEmail)` using `origin.authorEmail` (the pre-redaction value), not the already-redacted one, which is what the snippet above does — verify this is correct once written, since a subtle reordering bug here would silently degrade every pseudonym to name-only (still functional, but weaker stability guarantee than intended).

- [ ] **Step 4: Wire the new CLI flag**

In `bin/agentic-security.js`, mirroring `--include-author-email`'s exact chain: add `--pseudonymize-authors` to flag parsing, set `_provFlags.pseudonymize = true`, set `process.env.AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS = '1'`. In `report/index.js`'s `_normalizedProvenance`, read this env var the same way `includeEmail` is read, and pass `pseudonymize` through to `redactFindingProvenance`.

Also check `mcp/tools.js` — this session's audit confirmed `redactFindingProvenance` is called there too (a second real output funnel); wire the same flag through if that boundary has an equivalent policy-flag mechanism, or note explicitly if it doesn't and this is out of scope for MCP (mcp/tools.js may not have a CLI-flag-equivalent config surface — investigate and report, don't assume).

- [ ] **Step 5: Write tests**

```js
// Add wherever redactFindingProvenance's existing tests live:

test('pseudonymizeAuthor: same email always produces the same pseudonym', () => {
  const p1 = pseudonymizeAuthor('Jamie Chen', 'jamie@example.com');
  const p2 = pseudonymizeAuthor('J. Chen', 'jamie@example.com'); // different display name, same email
  assert.equal(p1, p2, 'stable identity must survive a display-name change for the same email');
});

test('pseudonymizeAuthor: different authors produce different pseudonyms', () => {
  const p1 = pseudonymizeAuthor('Alice', 'alice@example.com');
  const p2 = pseudonymizeAuthor('Bob', 'bob@example.com');
  assert.notEqual(p1, p2);
});

test('pseudonymizeAuthor: never reveals the real name or email in its output', () => {
  const p = pseudonymizeAuthor('Jamie Chen', 'jamie@example.com');
  assert.ok(!p.includes('Jamie'), 'pseudonym must not leak the real name');
  assert.ok(!p.includes('jamie@'), 'pseudonym must not leak the real email');
});

test('redactFindingProvenance: pseudonymize:true replaces authorName, pseudonymize:false leaves it untouched (backward compatible default)', () => {
  const fp = { findingOrigin: { authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', commit: 'abc' } };
  const withoutFlag = redactFindingProvenance(fp, {});
  assert.equal(withoutFlag.findingOrigin.authorName, 'Jamie Chen');
  const withFlag = redactFindingProvenance(fp, { pseudonymize: true });
  assert.match(withFlag.findingOrigin.authorName, /^Contributor-[0-9a-f]{8}$/);
});
```

Add a CLI-level test to `provenance-flags.test.js` proving `--pseudonymize-authors` genuinely changes real scan output (spawn the real CLI on a real git fixture, confirm the author name in output is a `Contributor-XXXXXXXX` pattern, not the real name).

- [ ] **Step 6: Run and verify**

Run the specific test files touched, foreground, confirm PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/schema.js scanner/bin/agentic-security.js scanner/src/report/index.js scanner/dist/ [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): --pseudonymize-authors, a stable one-way author pseudonym (PRD Section 8)

Mirrors --include-author-email's existing flag-wiring pattern exactly.
pseudonymizeAuthor() derives a deterministic Contributor-XXXXXXXX id from
authorEmail (falling back to authorName), so a reader can tell two
findings share an author without learning who that author is.
EOF
)"
```

(Rebuild `dist/` since `bin/agentic-security.js` changed.)

---

### Task 5: provenance-cache retention policy — split cache from lifecycle into separate top-level directories

**Files:**
- Modify: `scanner/src/posture/provenance/cache.js` (change storage path)
- Modify: `scanner/src/posture/artifact-registry.js` (split the registry entry)
- Test: extend `scanner/test/posture/provenance-cache.test.js`, `scanner/test/artifact-registry-completeness.test.js`, `scanner/test/retention-policy.test.js` (or wherever retention tests live)

**Interfaces:**
- Consumes: nothing new.
- Produces: cache files now live at `.agentic-security/provenance-cache/<hash>.json` instead of `.agentic-security/provenance/cache/<hash>.json`.

**This is a real, if minor, breaking change** — see the note at Step 3.

- [ ] **Step 1: Confirm the exact current storage paths**

Read `cache.js`'s exact `statePath(...)` call (this session's research found it as `statePath(scanRoot, 'provenance', 'cache', hash + '.json')` — re-confirm). Read `lifecycle.js`'s exact storage path (`statePath(scanRoot, 'provenance', 'lifecycle.json')` plus a `.lock` file — re-confirm). Read `artifact-registry.js`'s current single `provenance` entry in full, including its comment explaining why it deliberately has no `retentionClass`.

Grep the ENTIRE codebase (not just `provenance/`) for any other hardcoded reference to the `provenance/cache` path shape (e.g. `.agentic-security/provenance/cache` as a literal string anywhere, including in tests, docs, or scripts) — this session's research found none beyond `cache.js` itself, but re-verify since this plan is being executed later than that research.

- [ ] **Step 2: Change `cache.js`'s storage path**

```js
// Before:
// statePath(scanRoot, 'provenance', 'cache', hash + '.json')
// After:
// statePath(scanRoot, 'provenance-cache', hash + '.json')
```
Find the exact line(s) in `cache.js` that build this path (both the read and write sides — `cacheGet`/`cacheSet`, or wherever the path construction is centralized) and update both consistently. Prefer a single shared path-building helper within the file if one doesn't already exist, so read and write paths can never drift apart.

- [ ] **Step 3: Split the artifact-registry entry — and decide the migration question**

```js
// Before (one entry):
// { name: 'provenance', kind: 'dir', classification: 'generated', ... }

// After (two entries):
{ name: 'provenance-cache', kind: 'dir', classification: 'generated', retentionClass: 'cache', source: 'posture/provenance/cache.js -- pure HEAD-keyed memo, safely regenerable, no correctness dependency on being preserved' },
{ name: 'provenance', kind: 'dir', classification: 'generated', source: 'posture/provenance/lifecycle.js -- the introduce/remediate/reintroduce ledger. Deliberately NO retentionClass: this is permanent history, not a cache; auto-expiring it would silently lose lifecycle events a report may already have cited.' },
```

Check `RETENTION_DEFAULTS` in `retention-policy.js` for what the `'cache'` classification's actual TTL value is (this session's research flagged this needs confirming — read it now) and use that same class rather than inventing a new one, unless no `'cache'` class exists yet, in which case check what OTHER short-TTL classes exist and pick the closest match, or add a new class if genuinely none fits (explain your choice in the commit message either way).

**Migration decision (ruled here, not left to the implementer)**: existing installs' old `.agentic-security/provenance/cache/*.json` files become orphaned (invisible to the registry, un-swept by reset/retention, silently ignored by the new code which reads/writes only the new location) after this change. RULING: do NOT build a migration step. This is pure disk-cache content — safely regenerable, zero correctness impact, and the orphaned files will simply sit unused until a human notices and manually deletes `.agentic-security/provenance/cache/` (which by then contains nothing but stale, harmless JSON). Building an automated migration (detect old location, move files, handle partial failures) is disproportionate engineering for content that costs nothing to just leave behind and regenerate fresh. Document this explicitly in the commit message so it's a stated decision, not silent.

- [ ] **Step 4: Write tests**

```js
// Add to provenance-cache.test.js:
test('cache.js: writes to the new top-level provenance-cache/ directory, not nested under provenance/', async () => {
  // (build a real scanRoot, call cacheSet, confirm the file lands at
  // <scanRoot>/.agentic-security/provenance-cache/<hash>.json and NOT at
  // <scanRoot>/.agentic-security/provenance/cache/<hash>.json)
});

// Add to artifact-registry-completeness.test.js or wherever registry entries are unit-tested:
test('artifact-registry: provenance-cache and provenance are two separate top-level entries with different retention treatment', () => {
  // confirm isRegisteredArtifact('provenance-cache') and isRegisteredArtifact('provenance')
  // both return true, and retentionClassOf('provenance-cache') is truthy while
  // retentionClassOf('provenance') is falsy/undefined
});

// Add to whichever file tests retention-policy.js's findExpiredArtifacts:
test('findExpiredArtifacts: an old provenance-cache entry past its TTL is eligible for expiry; the lifecycle ledger never is', () => {
  // (construct a fixture with an aged provenance-cache/ dir and an aged
  // provenance/ dir, confirm only the former is reported expired)
});
```

Also run `cd scanner && node --test test/artifact-registry-completeness.test.js` to confirm the split doesn't trip the completeness drift guard (a `statePath()` call site with a literal that doesn't match a registry entry) — since this task changes what the real `statePath()` calls resolve to, the completeness check needs to see both new top-level names accounted for.

- [ ] **Step 5: Run full regression**

Run: `cd scanner && npm run test:posture` (foreground, timeout 300000) — this touches a widely-used shared path; broad regression check warranted. Pay special attention to any test that asserts on `.agentic-security/provenance/`'s directory CONTENTS (as opposed to just calling cache functions) — those may need updating to expect the new split layout.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/cache.js scanner/src/posture/artifact-registry.js [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): split the provenance cache into its own top-level, TTL-eligible directory (PRD Section 8)

.agentic-security/provenance/cache/ moves to .agentic-security/provenance-cache/
-- the artifact registry can only apply per-top-level-directory retention,
so the disk cache (safely regenerable, wants a TTL) and the lifecycle
ledger (must never auto-expire) had to physically separate to get
different retention treatment. Deliberately NOT migrating old-location
cache files -- pure disk cache, zero correctness cost to leave orphaned
and let a human clean up manually; not worth the engineering cost of an
automated migration for content this cheap to regenerate.
EOF
)"
```

---

### Task 6: provenance coverage success metric

**Files:**
- Modify: `scanner/src/posture/accuracy-scorecard.js`
- Test: extend `scanner/test/posture/accuracy-scorecard.test.js` (or wherever its tests live — check first)

**Interfaces:**
- Produces: a new rate row in the scorecard output, using the existing `formatRate(n, d)` convention.

- [ ] **Step 1: Read the existing rate-row pattern**

Read `accuracy-scorecard.js`'s `formatRate` function and at least 2 existing rate computations that use it, to match the exact established shape (`{n, d}` object, never a bare percentage). Read `report/index.js`'s existing `provenanceCoverage` raw-count computation (this session found it around lines 959-965, producing `{complete: N, partial: M, not_available: K, ...}`) — this is the source data to aggregate, not something to recompute from scratch.

- [ ] **Step 2: Add the coverage computation**

```js
// PRD Success Metrics: "Provenance coverage >=95% complete or uncommitted
// for P0-supported findings in full Git clones." P0-supported scope per
// the PRD's own Release Scope table: code (SAST), secrets, IaC/config,
// direct dependency findings. This metric will legitimately read LOW for
// secrets until [Task 11 commit] ships real secrets provenance -- that is
// CORRECT behavior for an honest metric, not a bug in this function.
export function computeProvenanceCoverage(scan) {
  const p0Findings = [
    ...(scan.findings || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []).filter((s) => s.type === 'vulnerable_dep' && s.isDirect),
  ];
  const d = p0Findings.length;
  const n = p0Findings.filter((f) => {
    const status = f.findingProvenance?.status;
    return status === 'complete' || status === 'uncommitted';
  }).length;
  return { n, d };
}
```

**Verify the exact field names/shapes used above against real current code before finalizing** — `scan.supplyChain`'s entries' `isDirect`/`type` fields were confirmed this session in a DIFFERENT context (M3's transitive-SCA work); re-confirm they're still named this way and that filtering to `isDirect` entries is the right way to scope "direct dependency findings" specifically (excluding transitive, since the PRD's P0 scope table names direct dependency findings, not transitive — transitive was explicitly P1).

Wire this into the scorecard's existing output-rendering pattern (find where other rate rows get rendered into the published `docs/SCORECARD.md` / `docs/scorecard.json` and add this one alongside them, matching the exact formatting convention).

- [ ] **Step 3: Write tests**

```js
test('computeProvenanceCoverage: counts complete+uncommitted against P0-scoped findings only', () => {
  const scan = {
    findings: [
      { findingProvenance: { status: 'complete' } },
      { findingProvenance: { status: 'partial' } },
    ],
    secrets: [
      { findingProvenance: { status: 'not_available' } }, // expected LOW until Task 11 ships
    ],
    supplyChain: [
      { type: 'vulnerable_dep', isDirect: true, findingProvenance: { status: 'uncommitted' } },
      { type: 'vulnerable_dep', isDirect: false, findingProvenance: { status: 'complete' } }, // transitive, must NOT count
    ],
  };
  const { n, d } = computeProvenanceCoverage(scan);
  assert.equal(d, 4, 'transitive SCA entry must be excluded from the P0-scoped denominator');
  assert.equal(n, 2, 'complete (findings) + uncommitted (direct SCA) count; partial and not_available do not');
});
```

- [ ] **Step 4: Run and verify**

Run the touched test file(s), foreground, confirm PASS. Optionally run `npm run scorecard` (per root CLAUDE.md's documented command) against a real scan to confirm the new row actually renders in `docs/SCORECARD.md` — do NOT commit a regenerated scorecard as part of THIS task unless explicitly instructed to (scorecard regeneration is normally a release-time step, per root CLAUDE.md's own documented process — check whether this plan's end-of-plan verification section already covers this, and if so, don't duplicate it here).

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/accuracy-scorecard.js [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): measure and publish provenance coverage against the PRD's 95% target

computeProvenanceCoverage() aggregates the existing per-status counts
already computed for SARIF output into a real {n,d} rate over P0-scoped
findings (SAST + secrets + direct SCA), following this codebase's
never-a-bare-percentage convention. Reads low for secrets until real
secrets provenance ships -- that's an honest number, not a bug.
EOF
)"
```

---

### Task 7: known-origin accuracy corpus and measurement

**Files:**
- Create: `bench/provenance-accuracy/` (new directory: `runner.mjs`, `BASELINE.json`, `CONTRIBUTING.md`, a `fixtures/` subdirectory)
- Modify: `scanner/package.json` (new `bench:provenance-accuracy:check` script)

**Interfaces:**
- Produces: a runnable accuracy gate, following `bench/layer-recall/`'s established structure.

**This is the largest single task in this plan — a new bench corpus, not a small metric wire-up.** Budget real implementation time.

- [ ] **Step 1: Study the existing bench structure to match conventions**

Read `bench/layer-recall/`'s directory structure IN FULL (its `runner.mjs`, `BASELINE.json` shape, `CONTRIBUTING.md`) — this is the closest existing precedent (a corpus + a runner + a baseline + a documented contribution process) and this new bench should match its conventions closely rather than inventing new ones. Also skim `bench/cve-replay/CONTRIBUTING.md` for how THAT corpus documents its own ground-truth-answer format, since "known-origin accuracy" is conceptually similar (a labeled answer key checked against real tool output).

- [ ] **Step 2: Design the fixture format**

Each fixture is a small, self-contained git history (built via `createGitFixture()`, the same helper used pervasively in `provenance-*.test.js`) with a documented TRUE origin commit for a specific finding. Propose a fixture manifest format, e.g.:

```js
// bench/provenance-accuracy/fixtures/direct-introduction.mjs
export const manifest = {
  id: 'direct-introduction',
  description: 'A commit adds string-concatenated SQL; parent is safe (PRD Scenario A)',
  build(fx) {
    fx.writeFile('server.js', 'db.query("SELECT * FROM t");\n');
    fx.commit('safe baseline');
    fx.writeFile('server.js', 'db.query("SELECT * FROM t WHERE id = " + req.query.id);\n');
    return fx.commit('introduce sqli'); // returns the commit this fixture asserts IS the true origin
  },
  finding: { file: 'server.js', line: 2, vuln: /SQL Injection/i }, // how to find the ONE finding this fixture is about, from a real scan's output
};
```

Build AT LEAST the 10-15 fixtures this scope calls for, covering (at minimum) the PRD's OWN named acceptance scenarios A through E (direct introduction, guard removal, rename, merge, reintroduction) since these are the PRD's own chosen canonical cases — reusing them here as the accuracy corpus's backbone is both efficient and directly traceable back to the PRD's own stated examples. Add a few more covering direct SCA (lockfile bump) and one shallow-clone/partial case (where the CORRECT answer is "correctly reports partial/earliest-observable," not a specific commit — accuracy for this class means "did it correctly decline to claim complete," not "did it name the right SHA").

- [ ] **Step 3: Write the runner**

```js
// bench/provenance-accuracy/runner.mjs
// Runs every fixture in fixtures/, resolves real provenance against it via
// the real runScan/annotateGitProvenance pipeline (not a mocked resolver --
// this must exercise the actual shipped code path), and scores exact-match
// against each fixture's documented true origin commit.
//
// Usage:
//   node bench/provenance-accuracy/runner.mjs                 # gate: exit 0/1
//   node bench/provenance-accuracy/runner.mjs --update-baseline
```

Follow `bench/layer-recall/runner.mjs`'s exact exit-code contract (0 clean, 1 drift, and whatever this project's convention is for an environment-error class distinct from a real accuracy miss — re-read that file's own exit-code documentation, don't invent a new convention). Publish `{n, d}` (matches followed accuracy computed, over total fixtures scoreable) plus a per-fixture pass/fail breakdown, never a bare aggregate percentage.

- [ ] **Step 4: Establish the baseline**

Run the new runner for real against the fixtures you built, record the ACTUAL result (should be very close to 100% given hand-built fixtures with unambiguous origins — if any fixture scores wrong, that's either a genuine bug worth investigating [stop and report, don't paper over it] or a badly-designed fixture worth fixing [more likely for a first-draft corpus]), and commit that real number as `BASELINE.json`. Do NOT pre-commit a 98% target and then adjust fixtures to hit it — the PRD's 98% is the aspiration; this baseline records reality, and if reality is below 98%, that's itself an honest, reportable finding, not something to hide by cherry-picking easy fixtures.

- [ ] **Step 5: Write `CONTRIBUTING.md`**

Document the fixture format, how to add a new fixture, and the same "never add an entry without confirming it scores correctly" discipline `bench/cve-replay/CONTRIBUTING.md` already establishes for its own corpus.

- [ ] **Step 6: Wire into package.json and run**

```bash
cd scanner && npm run bench:provenance-accuracy:check
```
Capture the real exit code and real output. Report it honestly in your task report — including the exact accuracy percentage achieved, not a rounded or optimistic characterization.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/provenance-accuracy/ scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): known-origin accuracy corpus and gate (PRD Success Metrics)

New bench/provenance-accuracy/ -- N hand-built fixtures with documented
ground-truth origin commits, covering the PRD's own named acceptance
scenarios A-E plus direct-SCA and a partial/shallow case. Baseline
records the REAL measured accuracy from this corpus, not a pre-committed
target -- see CONTRIBUTING.md for the discipline against padding the
corpus with easy fixtures to inflate the number.
EOF
)"
```

---

### Task 8: FR-PROV-017 — wire missing-control-resolver.js to a real live caller (rate-limit.js)

**Files:**
- Modify: `scanner/src/sast/rate-limit.js` (export the internal predicate)
- Modify: `scanner/src/posture/provenance/coordinator.js` (new branch, matching the `isScaLike` pattern)
- Modify: `scanner/src/posture/provenance/schema.js` (`PROVENANCE_METHOD` gains `MISSING_CONTROL_REGRESSION`)
- Test: extend `scanner/test/posture/provenance-coordinator.test.js` and/or a new `provenance-missing-control-wiring.test.js`

**Interfaces:**
- Consumes: `resolveMissingControl` from Task 3's prior M3 work (unchanged), `hasRateLimit` (newly exported this task).
- Produces: rate-limit findings whose `findingProvenance` correctly distinguishes "regression" (control was present, got removed — a real, provable event) from "was never present" (ordinary new-code finding, honestly `not_available`).

- [ ] **Step 1: Confirm rate-limit.js's real current shape**

Read `scanner/src/sast/rate-limit.js` in full — confirm `_hasRateLimit(content)`'s exact current signature and behavior (this session's research found it at line 34, not currently exported), and confirm the finding shapes it produces (`RATE_LIMIT_AUTH`/`RATE_LIMIT_AI`/`RATE_LIMIT_PAYMENT`/`RATE_LIMIT_CONTACT` — re-confirm these exact identifiers and what field they land on, e.g. `finding.vuln` or a dedicated marker).

- [ ] **Step 2: Export the predicate**

```js
export function hasRateLimit(content) {
  return _hasRateLimit(content); // or rename the internal function directly and export it -- your judgment on whichever is the smaller, cleaner diff once you're looking at the real code
}
```

- [ ] **Step 3: Give rate-limit findings a marker coordinator.js can branch on**

Add a field to rate-limit.js's finding construction (all 4 variants) that coordinator.js can use to route these findings to the missing-control path instead of the plain SAST path — e.g. `missingControlCandidate: true`. Do NOT string-match on `finding.id`/`finding.vuln` in coordinator.js (fragile, couples two unrelated modules' string formats) — an explicit boolean marker set at the point of finding construction is the more robust, self-documenting choice, matching how `isDirect`/`isTransitiveSca`-style markers already work elsewhere in this pipeline.

- [ ] **Step 4: Add the `MISSING_CONTROL_REGRESSION` method**

In `schema.js`'s `PROVENANCE_METHOD` enum, add `MISSING_CONTROL_REGRESSION: 'missing-control-regression'`.

- [ ] **Step 5: Extend coordinator.js's branching**

Read `coordinator.js`'s `resolveOne`/`resolveAndCache` current three-way `isSca`/`isTransitiveSca`/neither branch (the `isScaLike` pattern from M3 Task 7) in full, current state. Add a fourth case:

```js
const isMissingControlCandidate = !!finding.missingControlCandidate;
```

For this branch, instead of calling `resolveOrigin` (the plain SAST resolver), call `resolveMissingControl(scanRoot, { file: finding.file, predicate: async (root, sha, f) => { const { getBlobAtCommit } = await import('./git-evidence.js'); const blob = getBlobAtCommit(root, sha, f); return blob != null && hasRateLimit(blob); }, since: ctx.since, deadlineAt })`.

**Import `hasRateLimit` at the top of coordinator.js properly** — do not use a dynamic `import()` inside the predicate function for `hasRateLimit` itself (only `getBlobAtCommit` needs care about import placement per this file's existing conventions — check whether `git-evidence.js`'s functions are already statically imported at the top of `coordinator.js`, which they almost certainly are, and just reuse that existing import rather than a fresh dynamic one).

Map `resolveMissingControl`'s result:
- `status: 'complete'` with `removedAt` → this is a genuine regression. Build `findingProvenance` with `status: 'complete'`, `findingOrigin` populated from `removedAt` (map `removedAt.commit/authorName/authorDate/summary` onto the standard `findingOrigin` shape), `method: PROVENANCE_METHOD.MISSING_CONTROL_REGRESSION`, and a `limitations` entry noting this is a control-removal event, not an ordinary code-introduction event (so a reader isn't confused about why the "origin" here means something different than usual).
- `status: 'unknown'` → the control was never observed present in reachable history — this is the ORDINARY case for a rate-limit finding on genuinely new code, not a regression. Stamp `not_available` with limitation `'no prior version of this control was observed in reachable history — this may be new code rather than a regression'`.
- `status: 'budget_exhausted'` → pass through as-is, matching every other budget_exhausted path in this file.

- [ ] **Step 6: Write tests**

```js
// New fixture: a route file that HAD express-rate-limit imported and applied,
// then a later commit removes it, producing a real RATE_LIMIT_AUTH finding.
test('missing-control wiring: a genuine rate-limit REMOVAL resolves complete, attributed to the removal commit, method missing-control-regression', async () => {
  // (build with createGitFixture, run a real scan via runScan, find the
  // rate-limit finding, assert its findingProvenance.status === 'complete',
  // .method === 'missing-control-regression', .findingOrigin.commit ===
  // the removal commit's sha)
});

test('missing-control wiring: a rate-limit finding on code that NEVER had rate limiting resolves not_available, never falsely attributed to the root commit', async () => {
  // (a route with no rate limiting ever, single commit or multiple commits,
  // none of which ever had it -- confirm status:'not_available', and
  // explicitly confirm findingOrigin is null/absent, never fabricated)
});
```

- [ ] **Step 7: Run and verify**

Run the new/extended test files plus `cd scanner && npm run test:posture` (foreground, timeout 300000) — this changes coordinator.js's core branching logic, broad regression check is warranted.

Run `cd scanner && npm run bench:self-scan:check` — this changes what provenance METHOD gets attached to real rate-limit findings on THIS repo's own code (if any exist); confirm no drift, or if there is drift, investigate whether it's legitimate (a real rate-limit finding in this repo now correctly getting a `missing-control-regression` method where it previously got the generic SAST method) versus a bug.

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/sast/rate-limit.js scanner/src/posture/provenance/coordinator.js scanner/src/posture/provenance/schema.js [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): wire missing-control-resolver.js to rate-limit.js (FR-PROV-017)

The resolver has existed since M3, fully tested, with zero live callers.
rate-limit.js's finding shape ("a route lacks rate limiting") is exactly
the "control absent" question the resolver answers. Genuine removals
resolve complete/missing-control-regression, attributed to the removal
commit; code that never had rate limiting correctly resolves
not_available, never falsely attributed to the repository's first commit
(Scenario I, already proven at the resolver level -- this task proves it
end-to-end through a real, reachable finding for the first time).
EOF
)"
```

---

### Task 9: FR-PROV-022 — wire provider enrichment (GitHub/GitLab PR metadata + CODEOWNERS) into the live pipeline

**Files:**
- Modify: `scanner/src/posture/provenance/git-evidence.js` (new `getRemoteUrl`)
- Modify: `scanner/src/posture/provenance/schema.js` (new `providerEnrichment` field)
- Modify: `scanner/src/posture/provenance/coordinator.js` (once-per-scan config resolution, per-finding enrichment call with a hard cap)
- Test: extend `scanner/test/posture/provenance-providers.test.js`

**Interfaces:**
- Consumes: `resolveProviderConfig`, `fetchPRMetadata`, `fetchCodeowners` (all existing, M3 work, unchanged).
- Produces: `findingProvenance.providerEnrichment: {provider, prNumber, reviewers, approvals, mergedAt, codeowners}|null`.

- [ ] **Step 1: Add `getRemoteUrl` to git-evidence.js**

```js
export function getRemoteUrl(scanRoot) {
  const r = _run(scanRoot, ['remote', 'get-url', 'origin']);
  return r.ok ? r.stdout.trim() : null;
}
```
Match this file's exact existing `_run`/error-handling conventions (read a neighboring function first).

- [ ] **Step 2: Add the schema field**

In `schema.js`'s `emptyProvenance`, add `providerEnrichment: null` as a new top-level default field (a sibling to `branchIntroduction`, not nested inside it — PR/reviewer/CODEOWNERS metadata is a distinct concern from "which commit/branch," matching this project's existing convention of keeping origin/branch-entry/evidence-attribution as separate top-level objects rather than conflating them).

- [ ] **Step 3: Resolve provider config once per scan**

In `coordinator.js`'s `annotateGitProvenance` setup block — the SAME block that already computes `lineageKey` once per scan (M4's own precedent, confirmed this session) — add:
```js
const githubConfig = resolveProviderConfig(scanRoot, 'github');
const gitlabConfig = resolveProviderConfig(scanRoot, 'gitlab');
const providerConfig = githubConfig || gitlabConfig; // at most one provider active at a time; if both are somehow configured, github wins -- document this choice
const remoteUrl = providerConfig ? getRemoteUrl(scanRoot) : null; // never call getRemoteUrl (a git subprocess) when no provider is configured -- this is what makes "zero network calls when unconfigured" structural, not just tested
```
Store on `fullCtx.providerConfig`/`fullCtx.remoteUrl`.

- [ ] **Step 4: Add the hard per-scan enrichment cap**

```js
const MAX_PROVIDER_ENRICHMENTS_PER_SCAN = 20;
// (module-level constant, named clearly, documented: "an 8s-timeout-capped
// network call per finding is not automatically bounded by the scan's own
// deadlineAt -- N findings x up to 8s each could dwarf any reasonable scan
// budget. Capping the COUNT, not the per-call timeout, keeps the existing
// AbortSignal.timeout(8000) untouched while bounding the aggregate. Per
// this codebase's 'no silent caps' convention, this cap is disclosed in
// findingProvenance.limitations for every finding that would have
// qualified but didn't get enrichment because the cap was already spent.")
```
Thread a per-scan counter through `fullCtx` (e.g. `fullCtx.providerEnrichmentsRemaining = MAX_PROVIDER_ENRICHMENTS_PER_SCAN`, decremented each time an enrichment call is actually attempted, checked before each attempt).

- [ ] **Step 5: Call the enrichment in the 'complete' status branch**

In `coordinator.js`'s `'complete'`-status construction block (where `findingOrigin` is finalized), after the existing fields, if `ctx.providerConfig` is set AND `ctx.providerEnrichmentsRemaining > 0` AND `deadlineAt` hasn't passed:
```js
if (ctx.providerConfig && ctx.providerEnrichmentsRemaining > 0 && !(deadlineAt && Date.now() > deadlineAt)) {
  ctx.providerEnrichmentsRemaining--;
  const provider = ctx.providerConfig === githubConfig ? 'github' : 'gitlab'; // however you actually track which one was resolved -- your judgment on the cleanest way to carry this alongside providerConfig
  const fetchFn = provider === 'github' ? fetchPRMetadata : fetchPRMetadataGitlab; // match the REAL export names from providers/github.js vs providers/gitlab.js -- confirm exact names before writing this
  const pr = await fetchFn(scanRoot, originResult.findingOrigin.commit, ctx.remoteUrl, ctx.providerConfig);
  if (pr) {
    const codeowners = await fetchCodeownersFn(scanRoot, ctx.remoteUrl, ctx.providerConfig);
    provenance.providerEnrichment = { provider, prNumber: pr.prNumber, reviewers: pr.reviewers, approvals: pr.approvals, mergedAt: pr.mergedAt, codeowners: codeowners || [] };
  }
} else if (ctx.providerConfig && ctx.providerEnrichmentsRemaining === 0) {
  provenance.limitations.push(`provider enrichment cap (${MAX_PROVIDER_ENRICHMENTS_PER_SCAN}/scan) reached; not attempted for this finding`);
}
```

**This pseudocode has a deliberately-left decision point** (`provider === 'github' ? fetchPRMetadata : fetchPRMetadataGitlab` — the real gitlab function is likely also just named `fetchPRMetadata`, exported from a DIFFERENT module `providers/gitlab.js`, not a differently-named function in the same module — resolve this correctly by reading both files' real exports before finalizing, don't ship a naming collision or a wrong import).

- [ ] **Step 6: Write tests**

```js
// Extend provenance-providers.test.js with an END-TO-END test through
// annotateGitProvenance (not just the provider functions in isolation):

test('annotateGitProvenance: zero network calls when no provider is configured (end-to-end)', async () => {
  // spy on global.fetch, run a real scan through annotateGitProvenance with
  // no provenance-providers.yml and no token env vars, assert fetch was
  // never called -- even though findings resolve to 'complete' status
});

test('annotateGitProvenance: a configured provider enriches a complete-status finding with real-shaped PR metadata', async () => {
  // stub fetch to return a realistic PR payload, confirm
  // findingProvenance.providerEnrichment is populated correctly
});

test('annotateGitProvenance: the per-scan enrichment cap is honored and disclosed', async () => {
  // configure a provider, produce more complete-status findings than
  // MAX_PROVIDER_ENRICHMENTS_PER_SCAN, confirm only the cap's worth get
  // providerEnrichment populated and the rest carry the cap-reached
  // limitation string
});
```

- [ ] **Step 7: Run and verify**

Run `cd scanner && node --test test/posture/provenance-providers.test.js` (foreground, timeout 60000). Run `cd scanner && npm run test:posture` (foreground, timeout 300000) — broad regression check since this touches coordinator.js's core annotation flow.

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/git-evidence.js scanner/src/posture/provenance/schema.js scanner/src/posture/provenance/coordinator.js [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): wire GitHub/GitLab provider enrichment into the live annotation pass (FR-PROV-022)

Provider functions have existed since M3, hermetic and tested, with zero
live callers. Config resolved once per scan (not per-finding), so "zero
network calls when unconfigured" is structural, not just tested. A hard
per-scan cap (20 findings) bounds the aggregate cost of an 8s-per-call
timeout that isn't itself aware of the scan's own deadlineAt budget --
disclosed in limitations for any finding the cap skipped, per this
codebase's no-silent-caps convention.
EOF
)"
```

---

### Task 10: FR-PROV-029 — close the performance SLO gap by skipping the annotator pipeline in historical replay

**Files:**
- Modify: `scanner/src/engine.js` (`runFullScan`, new `skipAnnotators` option)
- Modify: `scanner/src/posture/provenance/predicate-replay.js` (`replayAt`, pass the new option)
- Test: extend `scanner/test/posture/provenance-origin-resolver.test.js`, run `bench/provenance/`

**This task is correctness-critical** — read the verification step carefully before touching `engine.js`.

- [ ] **Step 1: Verify `computeStableId`'s field dependencies before touching anything**

Read `scanner/src/posture/stable-id.js`'s `computeStableId(f)` in full. Confirm it ONLY reads raw detector-output fields already present the moment a detector emits a finding (rule identity via its `ruleId`/`cwe`/`family`/`parser`/`vuln` fallback chain, `file`, `line`, a normalized sink/snippet shape, path lineage) — and confirm NONE of these fields are ever SET or MODIFIED by any of the ~54 annotators that run after detection (`annotateConfidence`, `annotateCalibratedConfidence`, `annotateExploitability`, etc.). This is the safety property the whole fix depends on: if `computeStableId` (directly, or via some field it reads) depended on ANY annotator's output, skipping annotators would silently change stableIds computed during historical replay versus a normal scan, which would break the whole "does this historical commit's finding match the CURRENT finding's stableId" comparison `predicate-replay.js` exists to do.

**Do this verification empirically, not just by reading**: run a real scan with and without the annotator-skip (temporarily, in a scratch script — don't ship this scratch code) and confirm `computeStableId`'s output is byte-identical for the same finding either way, before proceeding to Step 2. If it is NOT identical, STOP — this means the fix as designed is unsafe and needs redesign (perhaps annotators need to run but their output discarded rather than skipped, which defeats the performance goal — escalate this as a real blocker in your report rather than shipping a subtly-broken optimization).

- [ ] **Step 2: Add the `skipAnnotators` option to `runFullScan`**

Read `engine.js`'s `runFullScan` function signature and find the exact point where detector output (`finalFindings`/`aSecrets`/`aLogic`) is finalized and the annotator pipeline begins (this session's research located this transition around line 9360, but re-confirm the exact current line — this file changes often). Guard the entire annotator block:

```js
export async function runFullScan(opts, cb) {
  // ... existing setup, detector execution, unchanged ...

  // [Location of the ~54-annotator pipeline block]
  if (!opts.skipAnnotators) {
    // ... all 54 annotators, unchanged, exactly as they are today ...
  }

  // ... existing finalization/return, unchanged ...
}
```

**Be extremely careful about what happens AFTER the annotator block if you guard it** — some later code may assume annotator-set fields exist (e.g. a finalization step that reads `f.confidence` unconditionally). Trace forward from the annotator block to `runFullScan`'s actual `return`/callback invocation and confirm nothing downstream of the guarded block throws or produces garbage when annotators were skipped. If something does, either move `skipAnnotators`'s guard to a narrower scope (skip only the annotators predicate-replay genuinely doesn't need, not literally everything) or add defensive fallbacks at the specific downstream read sites — your judgment on which is cleaner once you see the real code, but do not ship a guard that leaves the function in a half-finished state for its OTHER callers (every caller of `runFullScan` that does NOT pass `skipAnnotators` must see zero behavior change — this option must be 100% opt-in and invisible to every existing caller).

- [ ] **Step 3: Update `predicate-replay.js`'s `replayAt` to request the fast path**

```js
// Before:
// const { scan } = await runFullScan({ fileContents, scanRoot, provenance: false }, () => {});
// After:
const { scan } = await runFullScan({ fileContents, scanRoot, provenance: false, skipAnnotators: true }, () => {});
```

- [ ] **Step 4: Run the FULL existing provenance test suite — this is the real safety net**

```bash
cd scanner && npm run test:posture
```
Every existing provenance test that exercises real resolution (the large majority of `provenance-*.test.js`) implicitly depends on `replayAt` continuing to correctly identify whether a historical commit's blob contains a matching finding. If `skipAnnotators` broke anything about that matching (not just `computeStableId` directly, but any OTHER field the matching logic in `replayAt` reads — re-check `replayAt`'s full body, not just the `computeStableId` call, for anything else it inspects on the replayed `scan` object), this run will catch it. Read the actual pass/fail output; do not assume clean just because the command exits.

- [ ] **Step 5: Measure the real improvement**

```bash
cd scanner && npm run build && npm run bench:provenance:check
```
Read the REAL new overhead ratio from this run's own output — do not estimate or assume. Report it precisely (e.g. "overhead dropped from 30.71x to Nx"). This will very likely still be far above the PRD's literal 30% target (the annotator-skip is the single biggest lever identified by research, but the bench's own fixture-size-driven ratio inflation, documented in the bench's own header comments, means even a large absolute improvement may not reach 1.3x) — report the real number honestly, do not characterize a large relative improvement as "meeting the target" if it numerically doesn't. If the new number represents genuine, large improvement (even if still short of 30%), re-baseline `bench/provenance/BASELINE.json` (`npm run bench:provenance:update-baseline`) and say so plainly in the commit message, matching this project's own established discipline against silently accepting a worse-than-expected number without comment — the same discipline applies in reverse here: don't silently under-claim a real improvement either.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/engine.js scanner/src/posture/provenance/predicate-replay.js scanner/dist/ bench/provenance/BASELINE.json bench/provenance/history.jsonl
git commit -m "$(cat <<'EOF'
perf(provenance): skip the annotator pipeline during historical replay (FR-PROV-029)

predicate-replay.js's replayAt only ever reads scan.findings/secrets to
compute a stableId match -- it never used any of runFullScan's ~54
post-detection annotators' output, yet paid their full cost (measured
~39ms fixed overhead per call regardless of file size) on every one of
the ~2 replay calls per finding the resolution walk already makes.
skipAnnotators:true guards the entire annotator block; every OTHER
runFullScan caller is unaffected (the option defaults false/absent).
Verified computeStableId's output is byte-identical with and without
annotators before shipping this, since a silent stableId drift would
have broken historical-vs-current finding matching.

Real measured overhead: [FILL IN ACTUAL BEFORE/AFTER NUMBERS FROM STEP 5]
-- [state plainly whether this closes the PRD's 30% target or falls short,
and by how much, per this project's own no-silent-numbers discipline].
EOF
)"
```

**Do not pre-fill the bracketed numbers above with a guess — the implementer must run Step 5 for real and put the actual measured numbers in the actual commit message.**

---

### Task 11: real origin resolution for `scan.secrets` and `scan.logicVulns`

**Files:**
- Modify: `scanner/src/engine.js` (stableId backfill for secrets + blameable logicVulns, two new `annotateGitProvenance` calls, narrowed backstop for synthetic-line logicVulns)
- Modify: `scanner/src/posture/provenance/predicate-replay.js` (`replayAt`'s candidate pool gains `scan.logicVulns`)
- Test: new fixtures under `scanner/test/fixtures/`, extend `scanner/test/posture/provenance-coordinator.test.js` or a new dedicated test file

**Read the Global Research Findings section at the top of this plan before starting — the critical `predicate-replay.js` trap and the synthetic-producer scope correction are both binding context for this task, established by dedicated research, not to be re-derived from scratch.**

- [ ] **Step 1: Re-read `engine.js`'s current provenance block and `predicate-replay.js` fresh**

Both files will have shifted since this plan's research (Task 10 touches both directly, and other tasks may have landed first depending on dispatch order). Do not trust this plan's own line-number citations — find the real current locations of: the provenance block's 3 existing `annotateGitProvenance` calls, the `aSecrets`/`aLogic` finalization point (after their own filter/dedup steps, before the provenance block), and the existing `not_available` backstop loop for these two channels.

- [ ] **Step 2: Fix `predicate-replay.js` FIRST — this must land before or together with Step 4, never after**

```js
// In replayAt, change:
// const candidates = [...(scan.findings || []), ...(scan.secrets || [])];
// to:
const candidates = [...(scan.findings || []), ...(scan.secrets || []), ...(scan.logicVulns || [])];
```

This is safe even though `scan.logicVulns` includes the 3 synthetic-line producers (license-policy/deploy-platform/stack-playbook) that read `scanRoot`-level files directly rather than from the passed `fileContents` — those producers are NEVER routed through `resolveOrigin` in the first place (see Step 4's classification), so `replayAt` is never asked to match against them; their presence in this array when SOME OTHER finding's replay runs is harmless (they just won't match that other finding's stableId). Document this landmine explicitly in a comment at this line for a future contributor who might be tempted to wire ALL of `aLogic` through provenance without reading this plan.

- [ ] **Step 3: Classify `aLogic` into blameable vs. synthetic**

```js
// Producers with a REAL, diffable source line (git-blame-eligible):
// scanLogicVulns, scanBusinessLogic, scanMiddlewareOrdering, scanReDoS,
// scanRegexReDoS, scanTodosNearSecurity, logic-claims.js's ingested claims.
//
// Producers with a FIXED PLACEHOLDER line (0 or 1) that is NOT a real
// source location -- routing these through git-blame-style resolution
// would fabricate a plausible-looking but meaningless origin (e.g.
// "package.json line 1" attributed to whatever commit last touched that
// line, unrelated to the actual license/platform/stack finding).
// Identifiable by a fixed id-string prefix -- confirmed stable across all
// three producers' current code:
const SYNTHETIC_LOGIC_PREFIXES = ['license-policy:', 'deploy-platform:', 'stack-playbook:'];
function isSyntheticLogicFinding(f) {
  return typeof f.id === 'string' && SYNTHETIC_LOGIC_PREFIXES.some((p) => f.id.startsWith(p));
}
```
Place this near the `aLogic`/`aSecrets` finalization point identified in Step 1.

- [ ] **Step 4: Backfill stableId for secrets and blameable logicVulns**

```js
// computeStableId's own ruleId() fallback chain already handles a missing
// f.ruleId gracefully (falls back to f.cwe, then f.family, then
// f.parser+f.vuln, then f.vuln alone) -- but scan.secrets findings set
// NEITHER ruleId NOR family NOR parser, so today they'd all collide onto
// the SAME rid (f.cwe, which is a fixed "CWE-798" for every secret type).
// Backfill a real, per-pattern ruleId here so "AWS Access Key" and
// "Exposed JWT Token" don't collide into one stableId.
for (const f of aSecrets) {
  if (!f.ruleId) f.ruleId = `secret:${slugify(f.vuln || 'unknown')}`;
}
const blameableLogic = aLogic.filter((f) => !isSyntheticLogicFinding(f));
const syntheticLogic = aLogic.filter(isSyntheticLogicFinding);
for (const f of blameableLogic) {
  if (!f.ruleId) f.ruleId = `logic:${slugify(f.vuln || 'unknown')}`;
}
annotateStableIds(aSecrets);
annotateStableIds(blameableLogic);
```

**Write `slugify` (or find an existing equivalent already used elsewhere in engine.js — check before writing a new one) as a small, deterministic string-to-identifier function** — lowercase, replace non-alphanumeric runs with a single `-`, trim. Confirm `annotateStableIds` is already imported in `engine.js` (it should be, since it's already called on `finalFindings`) — reuse that same import, don't add a duplicate.

- [ ] **Step 5: Add the two new `annotateGitProvenance` calls**

Right after the existing transitive-SCA call (the 3rd of 3 existing calls), reusing the SAME `provenanceCtx` object so the shared `deadlineAt`/budget invariant holds exactly as it does for the existing 3 calls:

```js
await annotateGitProvenance(aSecrets, { ...provenanceCtx, findingType: 'secret' });
await annotateGitProvenance(blameableLogic, { ...provenanceCtx, findingType: 'logic' });
```

**Confirm `coordinator.js`'s `resolveOne` genuinely doesn't need a case for `findingType: 'secret'`/`'logic'`** (per this plan's Global Research Findings: it doesn't — both fall through to the plain SAST path already). Passing `findingType` anyway is harmless (an unrecognized value that isn't `'sca'`/`'sca-transitive'` just falls through) and useful for future debugging/logging — keep it for clarity even though it's not functionally required today.

- [ ] **Step 6: Narrow the existing backstop loop**

Find the existing `for (const bucket of [aSecrets, aLogic]) { ... not_available deferred ... }` backstop block. Since `aSecrets` and `blameableLogic` now go through REAL resolution above, this backstop should now only cover: (a) `syntheticLogic` (always, permanently, honestly `not_available` — these can never get real resolution, by design), and (b) any finding in `aSecrets`/`blameableLogic` that the real `annotateGitProvenance` call somehow didn't reach (a defensive catch-all, matching this file's own documented pattern for the existing SCA backstop). Update the limitation string for the synthetic-logic case specifically to be accurate now that it's a PERMANENT, PRINCIPLED non-answer rather than a temporary "deferred to a later phase" — e.g. `'this finding describes dependency/config/policy state, not a single source line a commit introduced -- origin resolution does not apply'`.

- [ ] **Step 7: Write fixture tests**

```js
// New: a secrets-provenance fixture proving a real hardcoded credential's
// origin resolves correctly, and TWO different secret types in the same
// file/commit don't collide onto the same stableId.
test('secrets provenance: a real hardcoded AWS key resolves to its introducing commit', async () => {
  // (createGitFixture, write a file with a real-shaped AWS key pattern,
  // commit, run a real scan via runScan, find the secret finding, confirm
  // findingProvenance.status === 'complete' and .findingOrigin.commit
  // matches the introducing commit)
});

test('secrets provenance: two different secret types in the same file get DIFFERENT stableIds, not collided', async () => {
  // (a file with both an AWS key pattern and a JWT-shaped pattern, confirm
  // the two resulting findings have different f.stableId values)
});

// New: a logicVulns-provenance fixture (pick whichever blameable producer
// is easiest to trigger deterministically via a real scan -- scanReDoS or
// scanTodosNearSecurity are likely simplest).
test('logicVulns provenance: a real blameable logic finding resolves to its introducing commit', async () => {
  // ...
});

// Regression guard: the synthetic producers must NEVER get a fabricated origin.
test('logicVulns provenance: license-policy/deploy-platform/stack-playbook findings stay honestly not_available, never get a fabricated commit attribution', async () => {
  // (trigger one of the 3 synthetic producers via a real scan -- e.g. a
  // package.json with a policy-violating license -- confirm
  // findingProvenance.status === 'not_available' and the limitation text
  // explains why, and CRITICALLY confirm findingProvenance.findingOrigin
  // is null, proving no fabricated commit attribution ever leaked through)
});
```

- [ ] **Step 8: Run and verify**

Run the new test file(s) plus `cd scanner && npm run test:posture` (foreground, timeout 300000) — this is a significant change to `engine.js`'s core provenance wiring, full regression check mandatory.

Run `cd scanner && npm run bench:self-scan:check` and `npm run bench:cve-replay:check` — confirm no detection-shape drift (this task changes what `stableId` secrets/logicVulns findings carry, which could theoretically interact with any downstream consumer keyed on stableId, e.g. baseline comparison, suppression matching — investigate any drift rather than assuming it's benign).

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/engine.js scanner/src/posture/provenance/predicate-replay.js [test files]
git commit -m "$(cat <<'EOF'
feat(provenance): real origin resolution for secrets and (blameable) logicVulns findings (PRD P0 scope)

Both channels were permanently stamped not_available -- the PRD's own
Release Scope table names secrets as explicit P0 scope. Root cause was
never "can't compute a stableId" (computeStableId's fallback chain
already tolerates a missing ruleId) but "nobody backfills one, and nobody
calls annotateGitProvenance on these channels at all."

Critical fix bundled here, not separable: predicate-replay.js's replayAt
candidate pool included scan.secrets but NOT scan.logicVulns -- wiring
logicVulns into resolution without this would have made every logicVulns
finding silently and permanently resolve 'partial', never confirming a
real, confirmable origin.

scan.logicVulns is not one detector -- three of its ~9 producers
(license-policy, deploy-platform, stack-playbook) use a fixed placeholder
line (0 or 1), not a real source location. Routing those through
git-blame-style resolution would fabricate a plausible-looking but
meaningless commit attribution. They're excluded by id-prefix and stay
permanently, honestly not_available.
EOF
)"
```

---

## End-of-plan: final build + whole-branch verification

After Task 11 (the last task), before the final whole-branch review:

- [ ] Run `cd scanner && npm run build 2>&1 | tail -20` (foreground, timeout 120000) and confirm it completes without error.
- [ ] Run `cd scanner && npm test` (foreground, timeout 700000) and capture the REAL exit code from the run's own output. Compare failures against this session's established pre-existing-flaky-test signature (subprocess-spawn timeout). A NEW failure outside that signature is a real regression requiring investigation.
- [ ] Run `cd scanner && npm run bench:cve-replay:check` and `npm run bench:self-scan:check` (wiping stray `.agentic-security` dirs first) — both must pass; investigate and justify any drift rather than reflexively re-baselining.
- [ ] Run `cd scanner && npm run bench:provenance:check` and `npm run bench:provenance-accuracy:check` (the new gate from Task 7) — read and report the REAL numbers.
- [ ] Run `cd scanner && node --test test/no-dead-modules.test.js test/check-doc-drift.test.js test/artifact-registry-completeness.test.js` explicitly — this plan adds several new exports/fields/a new top-level state directory; update `scanner/src/posture/CLAUDE.md`'s "Finding provenance" module table and module count, and the root `CLAUDE.md`'s provenance row, if either gate flags drift (this exact class of doc-drift has been caught 3 times already in this project's history — do not make it a 4th silent gap).
- [ ] Re-run `npm run scorecard` (per root CLAUDE.md's documented release process) if Task 6's new coverage metric should appear in the published `docs/SCORECARD.md` — check whether this is in scope for this plan's own close-out or a separate release-time step, and note your decision either way.
