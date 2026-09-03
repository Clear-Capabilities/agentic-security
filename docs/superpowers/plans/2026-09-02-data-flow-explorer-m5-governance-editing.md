# Governance Editing Workflow (M5 deliverable #5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a CLI-only "propose an edit to `recipient-profiles.json`,
validate it, preview a diff, require explicit confirmation, back up the
current file, write atomically, and append a signed audit event" —
satisfying PRD line 1324's 5-part write contract without building the
genuinely risky HTTP interactive write surface this sub-project's own
scoping doc rules out of scope.

**Architecture:** `governance-edit.js` is the pure propose/validate/diff
engine (no I/O beyond reading the target file); `bin/agentic-security.js`
wires a `governance propose-edit` CLI verb around it, handling the
file-system write, backup, and audit-log call. Reuses three already-
shipped, already-tested primitives verbatim: `loadRecipientConfig`
(read + tolerant parse), a newly-exported `isValidRecipientConfigEntry`
(the real per-entry validator, currently private), and `auditCall`
(the same audit-log mechanism `apply_fix`/`apply_sca_upgrade` already
use).

**Tech Stack:** Node ESM, `node:test`, no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-governance-editing-scoping.md`

## Global Constraints

- CLI-only — no HTTP server route, no frontend/UI work. This is the
  sub-project's own core scoping ruling, not a shortcut: an HTTP write
  route needs real, separately-scoped security engineering (CSRF
  protection, a write-authorization mechanism distinct from the
  existing read-only session token) this sub-project does not attempt.
- Targets exactly one file: `recipient-profiles.json`
  (`RECIPIENT_CONFIG_FILENAME` from `recipient-registry.js`). No
  general config-editing framework.
- Never writes without an explicit `--yes` flag — omitting it prints
  the preview/diff and exits 0 without writing (a dry-run by default).
- Every write is preceded by a real backup copy of the current file
  content, and gated by a content-digest "version guard": if the
  caller's own `--base-digest` (computed when they read the file to
  build their patch) doesn't match the file's REAL current digest, the
  write is refused — a real "someone else edited this concurrently"
  guard, never silently overwritten.
- Every entry in the proposed `recipients` object is validated via the
  real, already-tested `isValidRecipientConfigEntry` before any write
  — a validation failure is a clear, non-writing error naming which
  key(s) failed.
- Every successful write appends a real audit event via `auditCall`
  (`src/mcp/audit.js`), reusing the exact same mechanism/log file
  `apply_fix`/`apply_sca_upgrade` already use — no new audit-log
  format.
- No new npm dependency.
- `isValidRecipientConfigEntry` is exported from `recipient-registry.js`
  (dropping its leading underscore, the established precedent this
  codebase uses when a private helper needs a second real consumer —
  e.g. `FR203_ARG0_DESTINATION_CATEGORIES` in `coverage.js`) — the
  function's own behavior is unchanged, only its visibility.

---

### Task 1: `governance-edit.js` — the propose/validate/diff engine

**Files:**
- Create: `scanner/src/lineage/governance-edit.js`
- Modify: `scanner/src/lineage/recipient-registry.js` (export
  `isValidRecipientConfigEntry`, drop the leading underscore at its
  one existing call site too)
- Test: `scanner/test/lineage/governance-edit.test.js`

**Interfaces:**
- Produces: `proposeGovernanceEdit(currentConfig, patch) ->
  {valid, errors, diff}` — pure, no file I/O. `currentConfig`/`patch`
  are both `{recipients: {...}}`-shaped objects (the same shape
  `loadRecipientConfig` returns/consumes). `errors` is
  `[{key, message}]`, non-empty iff `valid` is false. `diff` is
  `{added: string[], removed: string[], changed: [{key, before, after}]}`
  — computed regardless of validity, so an invalid patch still shows
  the operator what they were trying to do.
- Consumes: `isValidRecipientConfigEntry` (Task 1's own export from
  `recipient-registry.js`).

- [ ] **Step 1: Export `isValidRecipientConfigEntry` from `recipient-registry.js`**

Read the current private function first (`grep -n
"_isValidRecipientConfigEntry" scanner/src/lineage/recipient-registry.js`)
to confirm its exact real signature and body before editing — do not
guess it from this plan's own description. Rename it to
`isValidRecipientConfigEntry` (drop the leading underscore), add
`export` to its declaration, and update its one existing call site
inside `loadRecipientConfig` to use the new name. Behavior must be
byte-identical — this is a visibility change only.

- [ ] **Step 2: Run the existing recipient-registry tests to confirm no regression**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures (the pre-existing
`recipient-registry`/`recipient-wiring` tests must be unaffected by a
pure rename+export).

- [ ] **Step 3: Write failing tests for `governance-edit.js`**

Create `scanner/test/lineage/governance-edit.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { proposeGovernanceEdit } from '../../src/lineage/governance-edit.js';

function _validEntry(overrides = {}) {
  return {
    provider: 'Acme Analytics', serviceType: 'analytics', legalEntity: 'Acme Inc',
    processorRole: 'processor', servicePurpose: 'usage analytics',
    subprocessorChain: [], processingCountries: ['US'], dataResidencyCommitment: null,
    dpaStatus: 'in_place', transferMechanism: null, transferImpactReviewStatus: null,
    retentionCommitment: null, ...overrides,
  };
}

test('proposeGovernanceEdit: a well-formed patch adding a new recipient is valid, with a real diff', () => {
  const current = { recipients: {} };
  const patch = { recipients: { vendor1: _validEntry() } };
  const { valid, errors, diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
  assert.deepEqual(diff.added, ['vendor1']);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.changed, []);
});

test('proposeGovernanceEdit: removing a recipient is reflected in the diff', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { recipients: {} };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, ['vendor1']);
  assert.deepEqual(diff.added, []);
});

test('proposeGovernanceEdit: changing an existing recipient field is reflected in the diff as changed, not added+removed', () => {
  const current = { recipients: { vendor1: _validEntry({ dpaStatus: 'not_in_place' }) } };
  const patch = { recipients: { vendor1: _validEntry({ dpaStatus: 'in_place' }) } };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].key, 'vendor1');
  assert.equal(diff.changed[0].before.dpaStatus, 'not_in_place');
  assert.equal(diff.changed[0].after.dpaStatus, 'in_place');
});

test('proposeGovernanceEdit: an unchanged recipient never appears in the diff at all', () => {
  const entry = _validEntry();
  const current = { recipients: { vendor1: entry } };
  const patch = { recipients: { vendor1: { ...entry } } };
  const { diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.changed, []);
});

test('proposeGovernanceEdit: a malformed entry in the patch is rejected with a clear, per-key error, and never marked valid', () => {
  const current = { recipients: {} };
  const patch = { recipients: { vendor1: { provider: 'x' } } }; // missing required fields
  const { valid, errors } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.key === 'vendor1'));
});

test('proposeGovernanceEdit: the diff is still computed even when the patch is invalid, so the operator sees what they attempted', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { recipients: { vendor1: _validEntry(), vendor2: { provider: 'bad' } } };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.deepEqual(diff.added, ['vendor2']);
});

test('proposeGovernanceEdit: never throws on a malformed current/patch shape', () => {
  for (const bad of [null, undefined, {}, { recipients: null }]) {
    assert.doesNotThrow(() => proposeGovernanceEdit(bad, { recipients: {} }));
    assert.doesNotThrow(() => proposeGovernanceEdit({ recipients: {} }, bad));
  }
});
```

- [ ] **Step 4: Run to verify failure**

Run: `cd scanner && node --test test/lineage/governance-edit.test.js`
Expected: FAIL — module not found.

- [ ] **Step 5: Write `governance-edit.js`**

Create `scanner/src/lineage/governance-edit.js`:

```js
// governance-edit.js — M5 deliverable #5 (PRD line 1324's 5-part write
// contract: preview, validation, backup/version guard, confirmation,
// audit event). A CLI-only workflow for proposing a validated,
// reviewable edit to recipient-profiles.json — the one governance
// config file this codebase already has real, tested per-entry
// validation for (isValidRecipientConfigEntry, recipient-registry.js).
//
// Deliberately narrower than the PRD's own richer "interactive review/
// approve UI" vision — the HTTP-server-side interactive write surface
// (new routes, CSRF protection, a write-authorization mechanism beyond
// the existing read-only session token) is real, separately-scoped
// future work, not attempted here. See this sub-project's own scoping
// doc for the full reasoning: no PRD acceptance criterion gates this
// deliverable at all, and every M4/M5 deliverable this session has
// shipped has been CLI-first with zero UI/HTTP-write work.
//
// This module is pure — no file I/O, no fs access. The CLI layer
// (bin/agentic-security.js's cmdGovernancePropose) owns reading the
// current file, writing the backup, writing the new content, and
// calling auditCall.

import { isValidRecipientConfigEntry } from './recipient-registry.js';

function _recipientsOf(config) {
  return config && typeof config === 'object' && config.recipients && typeof config.recipients === 'object'
    ? config.recipients
    : {};
}

function _validateEntries(recipients) {
  const errors = [];
  for (const [key, entry] of Object.entries(recipients)) {
    if (!isValidRecipientConfigEntry(entry)) {
      errors.push({ key, message: `recipient "${key}" is not a valid recipient-profile-shaped config entry` });
    }
  }
  return errors;
}

function _diffRecipients(currentRecipients, patchRecipients) {
  const added = [];
  const removed = [];
  const changed = [];
  const currentKeys = new Set(Object.keys(currentRecipients));
  const patchKeys = new Set(Object.keys(patchRecipients));
  for (const key of patchKeys) {
    if (!currentKeys.has(key)) { added.push(key); continue; }
    if (JSON.stringify(currentRecipients[key]) !== JSON.stringify(patchRecipients[key])) {
      changed.push({ key, before: currentRecipients[key], after: patchRecipients[key] });
    }
  }
  for (const key of currentKeys) {
    if (!patchKeys.has(key)) removed.push(key);
  }
  added.sort();
  removed.sort();
  changed.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { added, removed, changed };
}

/**
 * Propose a patch to a recipient-profiles.json-shaped config. Pure,
 * never throws, never touches the filesystem. `currentConfig`/`patch`
 * are both `{recipients: {...}}`-shaped; a malformed shape degrades to
 * an empty `recipients` object rather than throwing (mirrors
 * `loadRecipientConfig`'s own tolerant-degradation contract). Returns
 * `{valid, errors, diff}` — `diff` is always computed, even when
 * `valid` is false, so an operator can see what they attempted before
 * fixing a validation error.
 */
export function proposeGovernanceEdit(currentConfig, patch) {
  const currentRecipients = _recipientsOf(currentConfig);
  const patchRecipients = _recipientsOf(patch);
  const errors = _validateEntries(patchRecipients);
  const diff = _diffRecipients(currentRecipients, patchRecipients);
  return { valid: errors.length === 0, errors, diff };
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/governance-edit.test.js`
Expected: PASS, all 7 tests.

- [ ] **Step 7: Add the test file to the `test:lineage` script wiring**

Edit `scanner/package.json`'s `test:lineage` script — append
` test/lineage/governance-edit.test.js`.

- [ ] **Step 8: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/governance-edit.js scanner/src/lineage/recipient-registry.js scanner/test/lineage/governance-edit.test.js scanner/package.json
git commit -m "feat(lineage): add governance-edit.js, the propose/validate/diff engine for recipient-profiles.json edits"
```

---

### Task 2: CLI wiring (`governance propose-edit`) + backup/version-guard/audit + docs

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/` — new `commands/governance.md` (a new dispatcher,
  since this is not a mode of the existing `dataflow` dispatcher — it
  edits operator config, not the scanned graph)
- Modify: `scanner/src/lineage/CLAUDE.md`
- Test: `scanner/test/cli/governance-propose-edit.test.js` (new)
- Modify: `scanner/package.json`

**Interfaces:**
- Consumes: `proposeGovernanceEdit` (Task 1), `loadRecipientConfig`/
  `RECIPIENT_CONFIG_FILENAME` (`recipient-registry.js`, already
  shipped), `auditCall` (`src/mcp/audit.js`, already shipped),
  `statePath` (`posture/state-dir.js`, already shipped — the same
  helper `recipient-registry.js`'s own callers use to resolve the
  config file path from a scan root).
- Produces: `agentic-security governance propose-edit [path]
  --patch <patch-file.json> [--output <preview-file>] [--yes]`. Exit
  codes: `0` on success (both the dry-run-preview path and the real
  write path), `1` when validation fails (the patch itself is
  malformed), `2` on a usage/argument error (missing `--patch`, an
  unreadable/malformed `--patch` file) or a version-guard rejection
  (the file changed since `--patch` was computed against it — see
  Step 3 below for the exact mechanism).

- [ ] **Step 1: Write the failing CLI test**

Create `scanner/test/cli/governance-propose-edit.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-governance-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _validEntry(overrides = {}) {
  return {
    provider: 'Acme Analytics', serviceType: 'analytics', legalEntity: 'Acme Inc',
    processorRole: 'processor', servicePurpose: 'usage analytics',
    subprocessorChain: [], processingCountries: ['US'], dataResidencyCommitment: null,
    dpaStatus: 'in_place', transferMechanism: null, transferImpactReviewStatus: null,
    retentionCommitment: null, ...overrides,
  };
}

function _writeConfig(root, recipients) {
  const configPath = statePath(root, 'recipient-profiles.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  const body = JSON.stringify({ recipients }, null, 2);
  fs.writeFileSync(configPath, body);
  return { configPath, body };
}

test('governance propose-edit: without --yes, previews the diff and does NOT write', () => {
  const root = _mkTmpProject();
  const { configPath, body: before } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(configPath, 'utf8'), before, 'the real config file must be untouched without --yes');
  const preview = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.deepEqual(preview.diff.added, ['vendor1']);
  assert.equal(preview.written, false);
});

test('governance propose-edit: with --yes, writes atomically, backs up the original, and appends a real audit event', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.ok(written.recipients.vendor1);
  const backups = fs.readdirSync(path.dirname(configPath)).filter((f) => f.startsWith('recipient-profiles.json.bak-'));
  assert.equal(backups.length, 1, 'exactly one backup file must exist after the first edit');
  const auditLogPath = statePath(root, 'mcp-audit.log');
  assert.ok(fs.existsSync(auditLogPath), 'a real audit-log entry must be appended');
  const auditContent = fs.readFileSync(auditLogPath, 'utf8');
  assert.match(auditContent, /governance_propose_edit/);
  assert.match(auditContent, /"outcome":"ok"/);
});

test('governance propose-edit: a malformed patch entry exits 1, never writes, never backs up', () => {
  const root = _mkTmpProject();
  const { configPath, body: before } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: { provider: 'x' } } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
  assert.equal(fs.readFileSync(configPath, 'utf8'), before);
  const backupCount = fs.readdirSync(path.dirname(configPath)).filter((f) => f.startsWith('recipient-profiles.json.bak-')).length;
  assert.equal(backupCount, 0);
});

test('governance propose-edit: --base-digest mismatch (a concurrent edit) is refused, exit 2, never writes', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  // Simulate a stale digest — computed against different content than
  // what's actually on disk now.
  const staleDigest = crypto.createHash('sha256').update('{"recipients":{"someone-else-edited-this":true}}').digest('hex');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes', '--base-digest', staleDigest], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /concurrent|changed|digest/i);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.deepEqual(written.recipients, {});
});

test('governance propose-edit: missing --patch exits 2', () => {
  const root = _mkTmpProject();
  _writeConfig(root, {});
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});
```

Before writing the implementation, confirm the REAL current shape of
`.agentic-security/mcp-audit.log` entries (`grep -n "writeAuditEntry\|
JSON.stringify" src/mcp/audit.js` and read the surrounding lines) so
the `/"outcome":"ok"/` regex above matches the real serialization —
adjust the test's own regex if the real format differs (e.g. spaced
JSON), don't assume this plan's own guess is exactly right.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/cli/governance-propose-edit.test.js`
Expected: FAIL — `governance` is not a recognized top-level command yet.

- [ ] **Step 3: Add the CLI handler**

In `scanner/bin/agentic-security.js`, find a natural spot near the
other top-level command handlers (search for `async function
cmdDataflowScenarioApply` or `async function cmdDataflowImpactAssess`
for the nearest sibling pattern) and add:

```js
// agentic-security governance propose-edit [path] --patch <file>
// [--output <file>] [--yes] [--base-digest <hex>] — M5 deliverable #5.
// Proposes a validated, reviewable edit to recipient-profiles.json.
// Without --yes: computes and previews the diff, writes nothing.
// With --yes: re-validates, checks the version guard, backs up the
// current file, writes the new content atomically, and appends a real
// audit event via auditCall. Exit codes: 0 success (preview or real
// write), 1 validation failure, 2 argument/version-guard problem.
async function cmdGovernancePropose(args) {
  const target = args._[2] || '.'; // args._ = ['governance', 'propose-edit', <path>?]
  const targetAbs = path.resolve(target);

  const patchFlag = args.flags.patch;
  if (!patchFlag || typeof patchFlag !== 'string') {
    process.stderr.write('agentic-security governance propose-edit: --patch <file> is required.\n');
    return 2;
  }
  let patch;
  try {
    patch = JSON.parse(fs.readFileSync(path.resolve(patchFlag), 'utf8'));
  } catch (e) {
    process.stderr.write(`agentic-security governance propose-edit: could not read/parse --patch file "${patchFlag}": ${e.message}\n`);
    return 2;
  }

  const { RECIPIENT_CONFIG_FILENAME, loadRecipientConfig } = await import('../src/lineage/recipient-registry.js');
  const { statePath } = await import('../src/posture/state-dir.js');
  const configPath = statePath(targetAbs, RECIPIENT_CONFIG_FILENAME);
  const currentRaw = fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf8') : JSON.stringify({ recipients: {} });
  const currentConfig = loadRecipientConfig(fs.existsSync(configPath) ? configPath : null);
  const currentDigest = crypto.createHash('sha256').update(currentRaw).digest('hex');

  const baseDigestFlag = args.flags['base-digest'];
  if (baseDigestFlag && baseDigestFlag !== currentDigest) {
    process.stderr.write(`agentic-security governance propose-edit: the config file changed since --base-digest was computed (a concurrent edit) — refusing to write. Re-read the current file and recompute your patch.\n`);
    return 2;
  }

  const { proposeGovernanceEdit } = await import('../src/lineage/governance-edit.js');
  const { valid, errors, diff } = proposeGovernanceEdit(currentConfig, patch);
  if (!valid) {
    process.stderr.write(`agentic-security governance propose-edit: --patch file failed validation:\n${errors.map((e) => `  ${e.key}: ${e.message}`).join('\n')}\n`);
    return 1;
  }

  const yes = !!args.flags.yes;
  let written = false;
  let backupPath = null;
  if (yes) {
    backupPath = `${configPath}.bak-${Date.now()}`;
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    if (fs.existsSync(configPath)) fs.copyFileSync(configPath, backupPath);
    fs.writeFileSync(configPath, JSON.stringify(patch, null, 2));
    written = true;
    const { auditCall } = await import('../src/mcp/audit.js');
    auditCall({
      sessionRoot: targetAbs, tool: 'governance_propose_edit',
      args: { file: RECIPIENT_CONFIG_FILENAME, added: diff.added, removed: diff.removed, changedKeys: diff.changed.map((c) => c.key) },
      outcome: 'ok',
    });
  }

  const report = { currentDigest, diff, written, backupPath };
  const outputPath = args.flags.output;
  if (outputPath) {
    fs.writeFileSync(path.resolve(outputPath), JSON.stringify(report, null, 2));
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
  return 0;
}
```

Check whether `crypto` is already imported at the top of
`bin/agentic-security.js` (`grep -n "^import \* as crypto\|require('crypto')" bin/agentic-security.js`) before adding a new import — reuse the
existing one if present, matching this file's own established
import-once convention.

- [ ] **Step 4: Wire the top-level dispatch**

`governance` is a NEW top-level command, not a `dataflow` subcommand
(it edits operator config, not the scanned graph) — find `main()`'s
own top-level `switch (command)` (search for `case 'dataflow':`) and
add a sibling case:

```js
      case 'governance': {
        const sub = args._[1];
        if (sub === 'propose-edit') { process.exit(await cmdGovernancePropose(args)); }
        else {
          process.stderr.write(`agentic-security governance: unrecognized sub-command "${sub}" — must be "propose-edit".\n`);
          process.exit(2);
        }
        break;
      }
```

Read the surrounding `switch` structure first (10-15 lines before and
after the `case 'dataflow':` block) to confirm the exact real
indentation/brace style and where the final `default:`/unknown-command
fallback lives, so this new case is inserted correctly and the
existing fallback still catches every other unmatched top-level
command.

- [ ] **Step 5: Update the top-level help text**

Find the `Commands:` help block (the same block `dataflow export`'s
own line lives in — search for `dataflow scenario apply`) and add a
new top-level entry:

```
  governance propose-edit [path] --patch <file.json> [--output <file>] [--yes] [--base-digest <hex>]
                               Propose a validated, reviewable edit to
                               recipient-profiles.json. Without --yes,
                               previews the diff and writes nothing.
```

- [ ] **Step 6: Run the CLI test**

Run: `cd scanner && node --test test/cli/governance-propose-edit.test.js`
Expected: PASS, all 5 tests. If the audit-log assertion's regex needs
adjusting to match the real serialized format (per Step 1's own note),
iterate here until green.

- [ ] **Step 7: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: exit 0. Confirm via `git status` on the WHOLE `dist/`
directory (never a targeted grep of only `dist/agentic-security.mjs` —
per this session's own established, repeatedly-proven gotcha).

- [ ] **Step 8: Add the new test file to `test:mcp`'s script wiring**

This test exercises `auditCall`'s own real log format, matching
`test:mcp`'s own stated scope ("MCP server + audit log") more closely
than `test:lineage`'s. Read `scanner/package.json`'s current
`test:mcp` script string first, then append
` test/cli/governance-propose-edit.test.js` to it. If, after reading
the real script, `test:server` or a different scoped script is a
closer fit for a CLI-subprocess-level test (matching how
`dataflow-scenario-cli.test.js`/`dataflow-impact-cli.test.js` were
each wired into `test:server` in the two prior M5 sub-projects), use
that scoped script instead — pick the one whose own stated purpose
(per `scanner/CLAUDE.md`'s own test-command table) most precisely
matches what this file actually tests, don't default to `test:lineage`
just because the engine module lives there.

- [ ] **Step 9: Write `commands/governance.md`**

A new slash-command dispatcher markdown file, following the exact
format of an existing single-mode dispatcher (read `commands/
dataflow.md`'s own frontmatter/heading structure first and mirror it)
— `description`/`argument-hint` frontmatter, a `## Governance propose
edit` section documenting the flags (mirroring `dataflow.md`'s own
"### Options" table format), an "### Examples" section, and the same
`## Implementation` bash block pattern every other command file uses
(`node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs
governance "$@"`). State plainly: CLI-only, no PRD acceptance
criterion gates this deliverable, the HTTP interactive write surface
is explicitly deferred, and every write backs up the prior file and
appends a real audit event.

- [ ] **Step 10: Update `scanner/src/lineage/CLAUDE.md`**

Add a new top-level section "Milestone 5, Governance Editing Workflow
(deliverable #5) — COMPLETE," mirroring the existing "Milestone 5,
Blast-Radius: Impact Assessment" section's own format — covering: the
real PRD correction (no acceptance criterion gates this deliverable at
all); the CLI-only ruling and why; the version-guard/backup/audit
mechanism; the `isValidRecipientConfigEntry` export (a visibility
change to an already-tested private function, not new validation
logic); and the explicit HTTP-write-surface deferral.

- [ ] **Step 11: Run the full test:lineage and (whichever scoped script Step 8 chose) suites**

Run: `cd scanner && npm run test:lineage && npm run test:mcp` (or
`test:server`, matching Step 8's own real choice)
Expected: PASS, 0 failures, both.

- [ ] **Step 12: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: PASS, 0 failures. Capture and read the real exit code
immediately after (`echo $?`) — do not infer success from output
length, and run this in the FOREGROUND or via a real background-and-
wait pattern (never fire-and-forget) — two of this session's own prior
M5 sub-projects had real coordination problems from an implementer
backgrounding this exact command and never checking back. If a
Chrome-resource-contention-shaped failure appears (a
`cmd-dataflow-export.test.js`/`export-image.test.js` test failing with
a `null`/killed status, unrelated to any file this task touches),
re-run just that file in isolation to confirm it passes alone before
concluding it's pre-existing environmental flakiness — this exact
pattern was confirmed multiple times already this session; verify it
reproduces the same way, don't just assume.

- [ ] **Step 13: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ commands/governance.md scanner/src/lineage/CLAUDE.md scanner/test/cli/governance-propose-edit.test.js scanner/package.json
git commit -m "feat(cli): wire governance propose-edit — validated, backed-up, audited recipient-profiles.json edits"
```

## Final Review Checklist (for the coordinator, not a task)

- Confirm the backup file is created BEFORE the new content is
  written, and that a failed write (e.g. a permissions error) would
  leave the backup intact and the original file unmodified — re-read
  the exact write-order in `cmdGovernancePropose` against this
  requirement, don't just trust the plan text matches the shipped
  code.
- Confirm the version-guard check happens BEFORE any validation or
  write — a concurrent-edit rejection must never partially validate or
  partially write first.
- Confirm `auditCall` is invoked ONLY on the real write path (`--yes`
  supplied AND validation passed AND the version guard passed) — never
  on a dry-run preview, never on a validation failure.
- Confirm `isValidRecipientConfigEntry`'s exported behavior is
  byte-identical to its prior private behavior — re-run the
  PRE-EXISTING `recipient-registry.test.js`/`recipient-wiring.test.js`
  suites (already covered by `test:lineage`, but worth a direct look)
  to confirm zero regressions from the rename+export.
- Re-run `npm run build` one final time after ALL doc-only edits land,
  and check `git status` on the whole `dist/` directory — the CLI
  help-text edit (Step 5) DOES touch bundled source, unlike the
  `.md`/`CLAUDE.md` edits.
