// F-AC05: the regression artifact the slice verifies is replayed by the shipped CLI in a fresh process that inherits only PATH, HOME
// and the operator's feature switches, with no part of the run that produced it; all four legs settle as recorded, and a copy whose
// patch was edited after verification is refused. The slice runs end to end, so this is skipped where the trust boundary cannot run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SLICE = path.join(HERE, '..', '..', '..', 'scripts', 'contract-slice-example.mjs');
const skip = sandboxAvailable() ? false : 'no confinement backend on this host';

test('F-AC05: the regression artifact replays from the file alone in a fresh process; a tampered copy is refused', { skip, timeout: 900_000 }, () => {
  const r = spawnSync(process.execPath, [SLICE, '--json'], { encoding: 'utf8', timeout: 850_000 });
  assert.equal(r.status, 0, r.stderr.slice(-2000));
  const run = JSON.parse(r.stdout);
  const s = run.stages.find((x) => x.name === 'regression replay in a fresh process');
  assert.ok(s, 'the slice has the fresh-process stage');
  assert.equal(s.status, 'ok', JSON.stringify(s));
  assert.equal(s.exit, 0); assert.equal(s.replayStatus, 'passed');
  assert.deepEqual(s.legs, ['original-positive:ok', 'patched-negative:ok', 'workflow-baseline:ok', 'workflow-preserved:ok']);
  assert.notEqual(s.tamperedExit, 0);
  assert.deepEqual(s.env.slice(0, 2), ['PATH', 'HOME'], 'nothing else from the producing run reaches the replay');
});
