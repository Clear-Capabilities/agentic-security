#!/usr/bin/env node
// A local, non-interactive portfolio recovery walk-through (DOC-003.AC01, DOC-003.AC03).
//
//   node scripts/portfolio-recovery-example.mjs
//
// Two SYNTHETIC repositories are planned into leased work units in a disposable store, and a virtual clock (milliseconds, passed
// as an argument, never read from the machine) drives the story:
//
//   1. a worker leases a unit and "crashes" (it never reports back);
//   2. after the lease expires a second worker takes the unit; the first worker's late result is refused as a stale attempt;
//   3. a result delivered twice is counted once;
//   4. a unit is blocked, shows as blocked and not as progress, and is released again;
//   5. a dependency digest changes (the policy), so the verified result is invalidated, kept as a stale record, and the unit
//      returns to pending; it counts again only after it is re-verified;
//   6. the final state is compared with a fresh run over the same inputs: the scoped results must be identical.
//
// Nothing here reaches a network, a provider or a repository. The store lives in the OS temp folder and is removed at the end.
// The `portfolio-assurance` feature is needed only by the `agentic-security portfolio progress` command, which is run last with
// the feature enabled for that one child process.
//
// Exit: 0 every step behaved as described / 1 one did not.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  planPortfolio, openStore, mutateStore, readStore, leaseUnit, startUnit, completeUnit, blockUnit, unblockUnit, progressOf, scopedResults,
} from '../scanner/src/posture/portfolio/work-units.js';
import { planResume, applyResume, inspectStale } from '../scanner/src/posture/portfolio/resume.js';
import { sha, DEPS, COMMIT } from '../scanner/test/portfolio/helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'scanner', 'bin', 'agentic-security.js');
let failed = 0;
const check = (ok, what) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed++; };
const line = (s) => console.log(s);

const plan = planPortfolio({
  repositories: [{ name: 'repo-a', commit: COMMIT }, { name: 'repo-b', commit: COMMIT }], authorized: ['repo-a', 'repo-b'],
  taskTypes: ['sast-scan'], requiredInputs: { 'sast-scan': ['source'] }, synthetic: true,
}).plan;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'portfolio-example-'));
const file = path.join(dir, 'store.json');
openStore(file, plan);
const ids = Object.keys(readStore(file).units).sort();
const result = (id, deps = DEPS) => ({ resultDigest: sha(`result-${id}`), dependencies: deps });
const show = (label) => { const p = progressOf(readStore(file)); line(`  ${label}: verified ${p.verified}/${p.total}, leased ${p.leased}, running ${p.running}, pending ${p.pending}, blocked ${p.blocked}, stale results ${p.staleResults}`); return p; };

try {
  line(`plan ${plan.id}: ${ids.length} units over 2 authorized repositories`);

  line('\n1. a worker leases a unit and crashes');
  const a = mutateStore(file, (s) => leaseUnit(s, { holder: 'worker-1', now: 0, ttlMs: 1000 }));
  mutateStore(file, (s) => startUnit(s, { unitId: a.unitId, attemptId: a.attemptId, now: 10 }));
  show('t=10ms, worker-1 running and silent');

  line('\n2. the lease expires; another worker takes the unit; the late result of the first is refused');
  const b = mutateStore(file, (s) => leaseUnit(s, { holder: 'worker-2', now: 5000, ttlMs: 1000, unitId: a.unitId }));
  check(b && b.unitId === a.unitId && b.attemptId !== a.attemptId, `worker-2 holds ${b.attemptId} (worker-1 held ${a.attemptId})`);
  const zombie = mutateStore(file, (s) => completeUnit(s, { unitId: a.unitId, attemptId: a.attemptId, ...result(a.unitId), now: 5100 }));
  check(zombie.ok === false && zombie.code === 'stale-attempt', `late result from the expired attempt: ${zombie.code}`);
  show('after the refusal, nothing counted');

  line('\n3. a result delivered twice is counted once');
  mutateStore(file, (s) => startUnit(s, { unitId: b.unitId, attemptId: b.attemptId, now: 5200 }));
  const first = mutateStore(file, (s) => completeUnit(s, { unitId: b.unitId, attemptId: b.attemptId, ...result(b.unitId), now: 5300 }));
  const again = mutateStore(file, (s) => completeUnit(s, { unitId: b.unitId, attemptId: b.attemptId, ...result(b.unitId), now: 5400 }));
  check(first.counted === true && again.duplicate === true && again.counted === false, `first delivery counted ${first.counted}, duplicate counted ${again.counted}`);
  check(show('after both deliveries').verified === 1, 'exactly one unit is verified');

  line('\n4. a blocked unit is not progress');
  const other = ids.find((id) => id !== a.unitId);
  mutateStore(file, (s) => blockUnit(s, { unitId: other, reason: 'a required input is missing (synthetic)', now: 6000 }));
  check(show('blocked').blocked === 1, 'the blocked unit is reported as blocked, not verified');
  mutateStore(file, (s) => unblockUnit(s, { unitId: other, now: 6100 }));
  const c = mutateStore(file, (s) => leaseUnit(s, { holder: 'worker-2', now: 6200, ttlMs: 1000, unitId: other }));
  mutateStore(file, (s) => startUnit(s, { unitId: c.unitId, attemptId: c.attemptId, now: 6210 }));
  mutateStore(file, (s) => completeUnit(s, { unitId: c.unitId, attemptId: c.attemptId, ...result(c.unitId), now: 6300 }));
  check(show('all units verified').verified === 2, 'both units verified');

  line('\n5. dependency invalidation: the policy digest changes');
  const changed = { ...DEPS, policy: sha('policy-v2') };
  const planned = planResume(readStore(file), () => changed);
  line(`  resume plan: reuse ${planned.reuse.length}, invalidate ${planned.invalidate.length} (changed: ${[...new Set(planned.invalidate.flatMap((i) => i.changed))].join(', ')})`);
  const invalidated = mutateStore(file, (s) => applyResume(s, planned, 7000));
  check(invalidated.length === 2, `${invalidated.length} verified results invalidated`);
  check(show('after invalidation').verified === 0, 'nothing counts until it is re-verified');
  check(inspectStale(readStore(file)).length === 2, 'the old results are kept as inspectable stale records');
  for (const id of ids) {
    const l = mutateStore(file, (s) => leaseUnit(s, { holder: 'worker-3', now: 7100, ttlMs: 1000, unitId: id }));
    mutateStore(file, (s) => startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: 7110 }));
    mutateStore(file, (s) => completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, ...result(id, changed), now: 7200 }));
  }
  check(show('re-verified under the new policy').verified === 2, 'both units verified again, generation advanced');

  line('\n6. convergence with a fresh run');
  const fresh = path.join(dir, 'fresh.json');
  openStore(fresh, plan);
  for (const id of ids) {
    const l = mutateStore(fresh, (s) => leaseUnit(s, { holder: 'worker-x', now: 0, ttlMs: 1000, unitId: id }));
    mutateStore(fresh, (s) => startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: 1 }));
    mutateStore(fresh, (s) => completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, ...result(id, changed), now: 2 }));
  }
  check(JSON.stringify(scopedResults(readStore(file))) === JSON.stringify(scopedResults(readStore(fresh))), 'the recovered run and a fresh run have identical scoped results');

  line('\n$ agentic-security portfolio progress --store store.json');
  const r = spawnSync(process.execPath, [CLI, 'portfolio', 'progress', '--store', file], {
    cwd: dir, encoding: 'utf8', timeout: 30000, env: { ...process.env, AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' },
  });
  for (const l of String(r.stdout + r.stderr).trim().split('\n').slice(0, 14)) line(`    | ${l}`);
  check(r.status === 0, `exit ${r.status}`);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
line(failed ? `\n${failed} step(s) did not behave as described` : '\nevery step behaved as described; the disposable store was removed');
process.exit(failed ? 1 : 0);
