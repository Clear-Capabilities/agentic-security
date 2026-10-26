// Incremental reuse measurement (child process only).
//
// Sequence on a private temp copy of the unit:
//   1. cold     incremental on, empty state: persists a baseline.
//   2. warm     incremental on, tree unchanged: every restorable summary should
//               be reusable and none invalidated.
//   3. edit     append a new function to one file, then compute what the engine
//               will reuse using the engine's OWN selection functions
//               (diffFileHashes, pickReusableSummaries) over the persisted
//               state, before running the scan.
//   4. warm-after-edit scan with incremental on, and a cold-after-edit scan of
//               a fresh copy with incremental off; findings must be identical
//               (warm/cold parity).
//
// Counts are of persisted summary units, not of functions in the program: a
// summary exists only for functions the taint engine analysed.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runUnit, listFiles } from './scan-unit.mjs';
import {
  readIncrementalState, diffFileHashes, hashFileContent, pickReusableSummaries,
} from '../../../scanner/src/dataflow/incremental.js';

function key(f) { return `${f.file}|${f.line}|${f.cwe}|${f.parser}|${f.severity}`; }

function summariesOf(state) {
  const payload = (state && state.summaries && state.summaries.summaries) || (state && state.summaries) || {};
  const callers = (state && state.summaries && state.summaries.callers) || {};
  return { payload, callers };
}

export async function incrementalProbe(spec) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dag-inc-'));
  const cold = fs.mkdtempSync(path.join(os.tmpdir(), 'dag-cold-'));
  try {
    fs.cpSync(spec.dir, tmp, { recursive: true });
    const env = { AGENTIC_SECURITY_INCREMENTAL: '1' };
    const mk = (id, dir) => ({ id, dir, prefix: spec.prefix, stateWrites: true, env });
    const r1 = await runUnit(mk(`${spec.id}#cold`, tmp));
    const s1 = readIncrementalState(tmp);
    const r2 = await runUnit(mk(`${spec.id}#warm`, tmp));
    const s2 = readIncrementalState(tmp);
    const { payload: before } = summariesOf(s1);

    const target = listFiles(tmp).find((f) => /\.(js|mjs)$/.test(f) && !f.includes('.agentic-security'));
    if (!target) return { id: spec.id, status: 'skipped', reason: 'no JS file to edit in this unit' };
    const rel = path.relative(tmp, target).split(path.sep).join('/');
    fs.appendFileSync(target, '\nfunction benchEditedFunction() { return 1; }\n');

    const prior = readIncrementalState(tmp);
    const { payload, callers } = summariesOf(prior);
    // Hash with the same function the engine uses; keys of prior.files are the
    // engine's own file keys, so map by suffix when it stores absolute paths.
    const priorKeys = Object.keys(prior.files || {});
    const curHashes = {};
    for (const k of priorKeys) {
      const abs = path.isAbsolute(k) ? k : path.join(tmp, k);
      curHashes[k] = fs.existsSync(abs) ? hashFileContent(fs.readFileSync(abs, 'utf8')) : null;
    }
    const hashesMatchEngineKeying = priorKeys.length > 0;
    const diff = diffFileHashes(prior.files || {}, Object.fromEntries(Object.entries(curHashes).filter(([, v]) => v !== null)));
    const changedFiles = [...diff.changed, ...diff.added, ...diff.removed];
    const changedQids = new Set();
    for (const q of Object.keys(payload)) {
      const f = q.split('::')[0];
      if (changedFiles.some((c) => c === f || c.endsWith(`/${f}`) || f.endsWith(`/${c}`))) changedQids.add(q);
    }
    const emptyEntry = Object.fromEntries(Object.entries(payload).filter(([, v]) => v && v.entryContext === 'empty'));
    const { reusable, invalidated } = pickReusableSummaries(emptyEntry, callers, changedQids);

    const r3 = await runUnit(mk(`${spec.id}#warm-edit`, tmp));
    fs.cpSync(spec.dir, cold, { recursive: true });
    fs.appendFileSync(path.join(cold, rel), '\nfunction benchEditedFunction() { return 1; }\n');
    const r4 = await runUnit({ id: `${spec.id}#cold-edit`, dir: cold, prefix: spec.prefix, stateWrites: true, env: { AGENTIC_SECURITY_INCREMENTAL: '0' } });

    const warmKeys = new Set(r3.findings.map(key));
    const coldKeys = new Set(r4.findings.map(key));
    const onlyWarm = [...warmKeys].filter((k) => !coldKeys.has(k));
    const onlyCold = [...coldKeys].filter((k) => !warmKeys.has(k));
    const total = Object.keys(payload).length;
    return {
      id: spec.id,
      status: 'ok',
      editedFile: rel,
      summaryUnits: total,
      restorableEmptyEntryUnits: Object.keys(emptyEntry).length,
      legacyDiscardedUnits: total - Object.keys(emptyEntry).length,
      changedFiles: changedFiles.length,
      changedUnits: changedQids.size,
      reusedUnits: reusable.size,
      invalidatedUnits: invalidated.size,
      engineFileKeysSeen: hashesMatchEngineKeying,
      unchangedWarmReusedAll: s2 ? Object.keys(summariesOf(s2).payload).length === Object.keys(before).length : null,
      parity: { warmFindings: warmKeys.size, coldFindings: coldKeys.size, onlyWarm: onlyWarm.length, onlyCold: onlyCold.length, equal: onlyWarm.length === 0 && onlyCold.length === 0 },
      timesMs: { cold: r1.ms, warm: r2.ms, warmAfterEdit: r3.ms, coldAfterEdit: r4.ms },
      peakRssMb: Math.max(r1.peakRssMb, r2.peakRssMb, r3.peakRssMb, r4.peakRssMb),
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(cold, { recursive: true, force: true });
  }
}
