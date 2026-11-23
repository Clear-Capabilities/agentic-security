// H-AC05 (optional, P2): the bounded state-machine check of service-contract approval. The real implementation has no
// counterexample within the bounds; four deliberately broken implementations each produce one, so a clean result means the check
// looked. The result carries its bounds, assumptions, the implementation files' hashes and the command that reproduces it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as REAL from '../../src/contracts/approval.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(HERE, '..', '..', '..', 'scripts', 'model-check', 'approval.mjs');
const { check } = await import(SCRIPT);

test('H-AC05: no counterexample within the bounds for the real implementation; the result states bounds, assumptions, linkage and command', () => {
  const r = check({ depth: 12, traceDepth: 3 });
  assert.equal(r.result, 'no-counterexample-within-bounds', JSON.stringify(r.counterexamples.slice(0, 3)));
  assert.ok(r.bounds.reachableAbstractStates >= 20 && r.bounds.unmergedTraces > 1000);
  assert.ok(r.assumptions.length >= 3);
  assert.deepEqual(r.implementation.map((i) => i.file), ['scanner/src/contracts/approval.js', 'scanner/src/posture/invariants/lifecycle.js']);
  assert.ok(r.implementation.every((i) => /^sha256:[0-9a-f]{64}$/.test(i.sha256)));
  assert.match(r.command, /^node scripts\/model-check\/approval\.mjs --depth 12 --trace-depth 3$/);
  assert.match(r.limits, /proves nothing about the application/);
});

test('H-AC05: each broken implementation yields a counterexample trace', () => {
  const mutants = {
    // an unlisted human is accepted as a reviewer
    'approve-any-human': { ...REAL, approveContract: (l, c, o) => REAL.approveContract(l, c, { ...o, policy: { id: 'x', reviewers: [o.actor.id] } }) },
    // expiry is never evaluated
    'ignore-expiry': { ...REAL, approvalState: (c, l, o) => REAL.approvalState(c, l, { ...o, now: undefined }) },
    // the reviewer list is not re-checked when the state is read
    'no-reverification': { ...REAL, approvalState: (c, l, o) => REAL.approvalState(c, l, { ...o, policy: { id: 'model-check', reviewers: ['dana'] } }) },
    // a revocation is recorded but leaves the approval in force
    'revoke-is-noop': { ...REAL, revokeContract: (l) => ({ ok: true, ledger: l, errors: [] }) },
  };
  for (const [name, impl] of Object.entries(mutants)) {
    const r = check({ depth: 12, traceDepth: 3, impl });
    assert.equal(r.result, 'counterexample', `${name} was not caught`);
    assert.ok(r.counterexamples[0].trace.length >= 1, name);
  }
});

test('H-AC05: the command in the result reproduces it (exit 0, the same result)', () => {
  const p = spawnSync(process.execPath, [SCRIPT, '--json', '--depth', '12', '--trace-depth', '3'], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(p.status, 0, p.stderr);
  const r = JSON.parse(p.stdout);
  assert.equal(r.result, 'no-counterexample-within-bounds');
  assert.deepEqual(r.bounds, check({ depth: 12, traceDepth: 3 }).bounds);
});
