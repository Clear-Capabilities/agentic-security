// Stage 2 measurement-completeness audit: recordTriage's per-family 10k cap
// only ever wrote on the way UP to the cap — the call that crossed it
// (row totals > 10_000) set row._capped = true in memory and returned
// without calling _write, so `_capped` never reached disk, and every call
// after that — any verdict, not just more of the same one — silently
// vanished with the on-disk row frozen one write short of the real
// crossing point.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { recordTriage } from '../src/posture/validator-metrics.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-valmetrics-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"validator-metrics-test"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function readMetrics(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'validator-metrics.json'), 'utf8'));
}

test('recordTriage accumulates tp/fp/wontfix counts per family', async () => {
  const p = await mkProject();
  try {
    recordTriage(p.dir, { family: 'sqli', verdict: 'tp', stableId: 'a' });
    recordTriage(p.dir, { family: 'sqli', verdict: 'tp', stableId: 'b' });
    const row = recordTriage(p.dir, { family: 'sqli', verdict: 'fp', stableId: 'c' });
    assert.deepEqual({ tp: row.tp, fp: row.fp, wontfix: row.wontfix }, { tp: 2, fp: 1, wontfix: 0 });
    assert.equal(readMetrics(p.dir).productionTriage.sqli.tp, 2);
  } finally { await p.cleanup(); }
});

test('recordTriage ignores an unknown verdict rather than corrupting the row', async () => {
  const p = await mkProject();
  try {
    assert.equal(recordTriage(p.dir, { family: 'sqli', verdict: 'bogus' }), null);
    assert.equal(fs.existsSync(path.join(p.dir, '.agentic-security', 'validator-metrics.json')), false);
  } finally { await p.cleanup(); }
});

test('recordTriage: the call that crosses the 10k cap persists _capped:true to disk', async () => {
  const p = await mkProject();
  try {
    // Seed a row one write short of the cap.
    for (let i = 0; i < 9999; i++) recordTriage(p.dir, { family: 'sqli', verdict: 'tp' });
    const crossing = recordTriage(p.dir, { family: 'sqli', verdict: 'tp' }); // total now 10_000, not yet > 10_000
    assert.equal(crossing._capped, undefined, 'exactly at 10_000 is not yet over the cap');
    const overCap = recordTriage(p.dir, { family: 'sqli', verdict: 'tp' }); // total now 10_001, crosses
    assert.equal(overCap._capped, true, 'the crossing call must set _capped');
    assert.equal(overCap.tp, 10_001, 'the crossing call\'s own increment must still be counted');
    const onDisk = readMetrics(p.dir).productionTriage.sqli;
    assert.equal(onDisk._capped, true, '_capped must be persisted at the moment it is set, not lost');
    assert.equal(onDisk.tp, 10_001, 'the crossing value itself must be persisted, not the pre-crossing value');
  } finally { await p.cleanup(); }
});

test('recordTriage: after the cap, subsequent calls of ANY verdict are frozen (return the capped row, no further writes)', async () => {
  const p = await mkProject();
  try {
    for (let i = 0; i < 10_001; i++) recordTriage(p.dir, { family: 'sqli', verdict: 'tp' });
    const frozenTp = readMetrics(p.dir).productionTriage.sqli.tp;
    // A DIFFERENT verdict after the cap must also be frozen, not silently
    // accepted — the bug dropped ALL post-cap writes, not just more 'tp'.
    const r = recordTriage(p.dir, { family: 'sqli', verdict: 'fp' });
    assert.equal(r._capped, true);
    assert.equal(r.fp, 0, 'an fp after the cap must not be silently counted either');
    assert.equal(readMetrics(p.dir).productionTriage.sqli.tp, frozenTp, 'the on-disk row must not drift after capping');
  } finally { await p.cleanup(); }
});
