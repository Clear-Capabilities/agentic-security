// DAG-05: the engine-facing half of cross-scan reuse.
//
// `ReplayHooks` is handed to `runTaintEngine` as `opts._replay`. It does two jobs:
//
//   * RECORD (every run): for each function, the findings it contributed to the
//     result (every pass, after the same de-duplication key the engine uses) and
//     its pre-pass exit state, so the next scan has something to reuse.
//   * REPLAY (warm run): for a function the plan proved clean, hand the engine its
//     recorded exit state and findings instead of re-walking its body.
//
// A function is replayable only when every one of these holds: the dependency
// plan says clean (own body, resolution, the whole closure and its cycle are
// unchanged), a complete record exists for it, and the record came from an
// analysis that converged. Anything less and the engine analyses it as before.

import { jsonSafeFinding } from './incremental.js';

const MAX_EXIT_PATHS = 4000;

export class ReplayHooks {
  /**
   * @param {object} o
   * @param {Set<string>} [o.clean]            qids that may be replayed (empty or absent: record only)
   * @param {Map<string,object>} [o.records]   prior records: qid -> { exit:[...], findings:[{key,obj}] }
   * @param {string} [o.generation]            generation id of the cache the records came from
   * @param {Map<string,string>} [o.closure]   qid -> closure fingerprint (for provenance)
   */
  constructor({ clean, records, generation, closure } = {}) {
    this.clean = clean || new Set();
    this.records = records || new Map();
    this.generation = generation || null;
    this.closure = closure || new Map();
    this._found = new Map();        // qid -> Map(key -> obj)   recorded this run
    this._unrecordable = new Set(); // qids whose findings could not be serialised
    this._exits = new Map();        // qid -> [path] recorded this run
    this.converged = false;
    this.mainLoop = null;           // Set<qid>: the functions this run's main loop covers (the first fnLimit by qid)
    this.replayed = new Set();      // qids actually skipped this run
    this.reusedFindingIds = new Set();
  }

  /**
   * The engine's main loop covers only the first `fnLimit` functions by qid, so a record
   * made while a function was outside it lacks that loop's findings. Replay needs the same
   * membership now as when the record was made.
   */
  setMainLoop(qids) { this.mainLoop = qids; }

  canSkip(qid) {
    if (!this.clean.has(qid)) return false;
    const r = this.records.get(qid);
    if (!r) return false;
    return !this.mainLoop || r.inMain === this.mainLoop.has(qid);
  }

  exitState(qid) {
    const r = this.records.get(qid);
    return new Set((r && r.exit) || []);
  }

  /** Recorded findings for a replayed function, cloned so the engine may mutate them. */
  findingsFor(qid) {
    const r = this.records.get(qid);
    if (!r) return [];
    this.replayed.add(qid);
    const out = [];
    for (const { key, obj } of r.findings || []) {
      const c = JSON.parse(JSON.stringify(obj));
      out.push({ key, obj: c });
    }
    return out;
  }

  noteReused(id) { this.reusedFindingIds.add(id); }

  /** Called from the engine's finding collector for every mapped finding. */
  record(qid, key, obj) {
    if (!qid) return;
    let m = this._found.get(qid);
    if (!m) { m = new Map(); this._found.set(qid, m); }
    if (m.has(key)) return;
    const c = jsonSafeFinding(obj);
    if (c === null) { this._unrecordable.add(qid); return; }
    m.set(key, c);
  }

  recordExitStates(exitByQid) {
    for (const [qid, set] of exitByQid) {
      const arr = [...set].filter((p) => typeof p === 'string').sort();
      this._exits.set(qid, arr);
    }
  }

  noteConverged(v) { this.converged = !!v; }

  /**
   * The records to persist for the next scan: a clean function carries its prior
   * record forward, every other function gets what was recorded this run. A
   * function with an unserialisable finding or an oversized exit state gets no
   * record, which makes it always recompute.
   */
  buildRecords(qids) {
    const out = {};
    for (const qid of qids) {
      if (this.replayed.has(qid)) {
        const r = this.records.get(qid);
        if (r) out[qid] = r;
        continue;
      }
      if (this._unrecordable.has(qid)) continue;
      const exit = this._exits.get(qid);
      if (!exit || exit.length > MAX_EXIT_PATHS) continue;
      const found = this._found.get(qid) || new Map();
      out[qid] = { exit, inMain: this.mainLoop ? this.mainLoop.has(qid) : true, findings: [...found].map(([key, obj]) => ({ key, obj })) };
    }
    return out;
  }
}
