// Tests for posture/remediation-ledger.js — M5 deliverable #6 (Blast-Radius:
// Remediation Command Center, FR-507 + AC-31), Task 2's own I/O half.
// Task 1 (scanner/src/lineage/remediation.js) shipped the pure fold/
// validateTransition state machine this module writes through; these tests
// exercise the impure ledger: locking, JSONL append, tolerant read, and the
// hash chain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { statePath, setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { foldRemediationLedger } from '../../src/lineage/remediation.js';
import {
  ledgerPaths,
  readLedgerEvents,
  latestEventHash,
  appendLedgerEvent,
} from '../../src/posture/remediation-ledger.js';

// Same temp-project helper shape test/cli/governance-propose-edit.test.js
// uses: a real temp dir plus a package.json marker, so isSafeStateDir passes.
function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-rem-ledger-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function _openedEvent(id, overrides = {}) {
  return { type: 'opened', id, owner: 'alice', dueDate: '2026-12-01', recommendedControl: 'mask-field', ...overrides };
}

// L/1
test('ledgerPaths resolves both paths under statePath, never a hand-joined string', () => {
  const root = _mkTmpProject();
  const { ledgerPath, lockPath } = ledgerPaths(root);
  assert.equal(ledgerPath, statePath(root, 'remediation', 'items.jsonl'));
  assert.equal(lockPath, statePath(root, 'remediation', 'items.lock'));
});

// L/2
test('readLedgerEvents on a missing file returns [], never throws', () => {
  const root = _mkTmpProject();
  assert.deepEqual(readLedgerEvents(root), []);
});

// L/3
test('round trip: append opened, readLedgerEvents returns exactly one event carrying prev: GENESIS', async () => {
  const root = _mkTmpProject();
  const res = await appendLedgerEvent(root, _openedEvent('item-1'));
  assert.equal(res.valid, true, JSON.stringify(res.errors));
  const events = readLedgerEvents(root);
  assert.equal(events.length, 1);
  assert.equal(events[0].prev, 'GENESIS');
  assert.equal(events[0].id, 'item-1');
});

// L/4
test('chain continuity: second event prev equals sha256 of the first line exact serialized text', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));
  const res2 = await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'in_progress' });
  assert.equal(res2.valid, true, JSON.stringify(res2.errors));

  const { ledgerPath } = ledgerPaths(root);
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 2);
  const expectedPrev = _sha(lines[0]);
  const secondEvent = JSON.parse(lines[1]);
  assert.equal(secondEvent.prev, expectedPrev);
});

// L/5
test('latestEventHash is GENESIS when empty/missing, then sha256 of the last line after an append', async () => {
  const root = _mkTmpProject();
  assert.equal(latestEventHash(root), 'GENESIS');
  await appendLedgerEvent(root, _openedEvent('item-1'));
  const { ledgerPath } = ledgerPaths(root);
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(latestEventHash(root), _sha(lines[0]));
});

// L/6
test('a torn tail is skipped, not fatal', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));
  await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'in_progress' });
  const { ledgerPath } = ledgerPaths(root);
  const beforeLines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(beforeLines.length, 2);
  fs.appendFileSync(ledgerPath, '{"type":"state_ch');

  const events = readLedgerEvents(root);
  assert.equal(events.length, 2);
  assert.equal(latestEventHash(root), _sha(beforeLines[1]));
});

// L/7
test('a tampered middle line breaks the chain and is reported: verifying prefix returned, rest dropped', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));
  await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'in_progress' });
  const { ledgerPath } = ledgerPaths(root);
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 2);

  // Tamper line 1's owner in place, preserving valid JSON.
  const tampered = JSON.parse(lines[0]);
  assert.equal(tampered.owner, 'alice');
  tampered.owner = 'mallory';
  const newLine0 = JSON.stringify(tampered);
  fs.writeFileSync(ledgerPath, [newLine0, lines[1]].join('\n') + '\n', 'utf8');

  const events = readLedgerEvents(root);
  // Line 1's own prev (GENESIS) is untouched by the tamper, so it still
  // verifies against genesis and IS returned (with the tampered content) —
  // it's line 2's prev (computed against the ORIGINAL line 1 text) that no
  // longer matches, breaking the chain from there on. Documented behavior:
  // the longest verifying PREFIX is returned, never the full stream.
  assert.equal(events.length, 1);
  assert.equal(events[0].owner, 'mallory');
  assert.equal(latestEventHash(root), _sha(newLine0));
});

// L/8
test('appendLedgerEvent REJECTS an illegal transition and writes nothing', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));
  const res = await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'verified' });
  assert.equal(res.valid, false);
  assert.ok(res.errors.length > 0);
  assert.ok(res.errors.some((e) => /verified/.test(e.message)), JSON.stringify(res.errors));
  const events = readLedgerEvents(root);
  assert.equal(events.length, 1);
});

// L/9
test('appendLedgerEvent rejects a second opened for an existing item id', async () => {
  const root = _mkTmpProject();
  const first = await appendLedgerEvent(root, _openedEvent('item-1'));
  assert.equal(first.valid, true, JSON.stringify(first.errors));
  const second = await appendLedgerEvent(root, _openedEvent('item-1'));
  assert.equal(second.valid, false);
  assert.ok(second.errors.length > 0);
  const events = readLedgerEvents(root);
  assert.equal(events.length, 1);
});

// L/10
test('concurrency: ~8 parallel appendLedgerEvent calls against one item serialize correctly', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));

  const calls = [];
  for (let i = 0; i < 8; i++) {
    calls.push(appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'in_progress' }));
  }
  const results = await Promise.all(calls);
  const succeeded = results.filter((r) => r.valid === true);
  const failed = results.filter((r) => r.valid === false);
  assert.equal(succeeded.length, 1, 'exactly one of the 8 identical transitions should be legal');
  assert.equal(failed.length, 7);

  const { ledgerPath } = ledgerPaths(root);
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 2, 'only the opened event plus the one successful transition were appended');
  for (const line of lines) {
    assert.doesNotThrow(() => JSON.parse(line));
  }

  const events = readLedgerEvents(root);
  assert.equal(events.length, 2, 'the chain verifies end to end with no interleaved/corrupted line');
  assert.equal(latestEventHash(root), _sha(lines[1]));

  const items = foldRemediationLedger(events);
  assert.equal(items['item-1'].state, 'in_progress');
});

// L/11
test('stale-lock reaping: a lockfile holding a certainly-dead PID does not wedge the write', async () => {
  const root = _mkTmpProject();
  const { lockPath } = ledgerPaths(root);
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  fs.writeFileSync(lockPath, String(2147483647));

  const res = await appendLedgerEvent(root, _openedEvent('item-1'));
  assert.equal(res.valid, true, JSON.stringify(res.errors));
  assert.equal(readLedgerEvents(root).length, 1);
});

// L/12
test('appendLedgerEvent refuses when isSafeStateDir is false, and creates no .agentic-security dir', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-rem-ledger-unsafe-'));
  const res = await appendLedgerEvent(root, _openedEvent('item-1'));
  assert.equal(res.valid, false);
  assert.ok(res.errors.length > 0);
  assert.equal(fs.existsSync(path.join(root, '.agentic-security')), false);
});

// L/13
test('appendLedgerEvent refuses when stateWritesEnabled() is false', async () => {
  const root = _mkTmpProject();
  setStateWritesEnabled(false);
  try {
    const res = await appendLedgerEvent(root, _openedEvent('item-1'));
    assert.equal(res.valid, false);
    assert.ok(res.errors.length > 0);
  } finally {
    setStateWritesEnabled(true);
  }
  assert.equal(readLedgerEvents(root).length, 0);
});

// L/14
test('foldRemediationLedger(readLedgerEvents(root)) over a multi-item ledger reproduces each real state', async () => {
  const root = _mkTmpProject();
  await appendLedgerEvent(root, _openedEvent('item-1'));
  await appendLedgerEvent(root, _openedEvent('item-2', { owner: 'bob' }));
  await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'in_progress' });
  await appendLedgerEvent(root, { type: 'state_changed', itemId: 'item-1', state: 'awaiting_verification' });
  await appendLedgerEvent(root, {
    type: 'accepted_risk', itemId: 'item-2',
    approver: 'carol', reason: 'low risk', scope: 'this deploy', expiration: '2026-12-31',
  });

  const items = foldRemediationLedger(readLedgerEvents(root));
  assert.equal(items['item-1'].state, 'awaiting_verification');
  assert.equal(items['item-1'].owner, 'alice');
  assert.equal(items['item-2'].state, 'accepted_risk');
  assert.equal(items['item-2'].exceptions.length, 1);
  assert.equal(items['item-2'].exceptions[0].approver, 'carol');
});
