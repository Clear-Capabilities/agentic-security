// E-04 / E-AC05: the approval ledger under interruption, corruption and duplicate delivery. A verified result is never reconstructed
// from a damaged or partial record, and a duplicated transition never grants progress twice.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { proposeContract, approveContract, approvalState, writeLedgerFile, readLedgerFile } from '../../src/contracts/approval.js';
import { recordTransition } from '../../src/posture/invariants/lifecycle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const contract = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'contract-slice', 'security', 'contracts', 'invoices-service', 'contract.json'), 'utf8'));
const lax = { sign: () => 'ff', verify: () => true };
const POLICY = { id: 'p', reviewers: ['dana'] };

test('an interrupted write leaves the previous ledger intact; a corrupt or truncated file is corrupt, never empty and never approval', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-faults-'));
  try {
    const file = path.join(dir, 'ledger.json');
    const p = proposeContract(null, contract, { actor: { id: 'd', kind: 'code' }, reason: 'r', signer: lax });
    assert.equal((await writeLedgerFile(file, p.ledger)).ok, true);
    const a = approveContract(p.ledger, contract, { actor: { id: 'dana', kind: 'human' }, reason: 'ok', policy: POLICY, signer: lax });
    // simulate a crash between writing the temp file and the rename: the temp exists, the target still holds the proposal
    fs.writeFileSync(`${file}.tmp-crashed`, JSON.stringify(a.ledger).slice(0, 40));
    const after = await readLedgerFile(file);
    assert.equal(after.ok, true); assert.equal(approvalState(contract, after.ledger, { signer: lax, policy: POLICY, now: '2026-11-22' }).state, 'proposed', 'the half-written approval did not land');
    await writeLedgerFile(file, a.ledger);
    assert.equal(approvalState(contract, (await readLedgerFile(file)).ledger, { signer: lax, policy: POLICY, now: '2026-11-22' }).state, 'approved');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').slice(0, 100));
    const corrupt = await readLedgerFile(file);
    assert.equal(corrupt.ok, false); assert.equal(corrupt.state, 'corrupt');
    assert.equal((await readLedgerFile(path.join(dir, 'missing.json'))).state, 'missing');
    const link = path.join(dir, 'link.json'); fs.symlinkSync(file, link);
    assert.equal((await writeLedgerFile(link, a.ledger)).ok, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('duplicate delivery of a transition is refused: an approval recorded twice is not progress twice', () => {
  const p = proposeContract(null, contract, { actor: { id: 'd', kind: 'code' }, reason: 'r', signer: lax });
  const again = proposeContract(p.ledger, contract, { actor: { id: 'd', kind: 'code' }, reason: 'r', signer: lax });
  assert.equal(again.ok, false); assert.equal(again.errors[0].code, 'already-recorded');
  const a = approveContract(p.ledger, contract, { actor: { id: 'dana', kind: 'human' }, reason: 'ok', policy: POLICY, signer: lax });
  const twice = approveContract(a.ledger, contract, { actor: { id: 'dana', kind: 'human' }, reason: 'ok', policy: POLICY, signer: lax });
  assert.equal(twice.ok, false); assert.equal(twice.errors[0].code, 'illegal-transition');
  assert.equal(a.ledger.records.length, 2);
  // a replayed record appended by hand breaks the chain rather than counting twice
  const replayed = { ...a.ledger, records: [...a.ledger.records, a.ledger.records[1]] };
  assert.equal(approvalState(contract, replayed, { signer: lax, policy: POLICY, now: '2026-11-22' }).state, 'approval-unverifiable');
  void recordTransition;
});
