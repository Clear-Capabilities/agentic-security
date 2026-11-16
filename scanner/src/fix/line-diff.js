// Line diff for patch scope (verified-remediation PRD FR-03, GAP-03).
//
// The patch bound used to be |lines(after) - lines(before)|, so rewriting 150 lines into 150 different lines measured zero. This is a
// real line diff: Myers' O(ND) shortest edit script over whole lines, returning hunks with exact before/after line ranges.
//
// Bounded: the edit distance search stops at MAX_EDIT_DISTANCE. Past that the diff is reported `approximate: true` and every line of both
// sides that is not in the common prefix or suffix counts as changed. That fallback can only OVER-count, never under-count, so a policy
// that reads it can be too strict but never too lenient.
//
// Pure: no fs, no clock.

const MAX_EDIT_DISTANCE = 4000;

export const splitLines = (text) => {
  if (text === null || text === undefined) return [];
  const s = String(text);
  if (s === '') return [];
  const lines = s.split('\n');
  if (lines[lines.length - 1] === '') lines.pop(); // a trailing newline does not add a line
  return lines;
};

// Myers forward search, returning the edit script as a list of ops over the trimmed middle.
function myers(a, b, maxD) {
  const n = a.length; const m = b.length; const max = n + m;
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace = [];
  for (let d = 0; d <= Math.min(max, maxD); d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
      else x = v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) return backtrack(trace, a, b, off, d);
    }
  }
  return null;
}

function backtrack(trace, a, b, off, dEnd) {
  const ops = [];
  let x = a.length; let y = b.length;
  for (let d = dEnd; d > 0; d--) {
    const v = trace[d];
    const k = x - y;
    const prevK = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? k + 1 : k - 1;
    const prevX = v[off + prevK]; const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { ops.push(['=', x - 1, y - 1]); x--; y--; }
    if (x === prevX) ops.push(['+', x, y - 1]); else ops.push(['-', x - 1, y]);
    x = prevX; y = prevY;
  }
  while (x > 0 && y > 0) { ops.push(['=', x - 1, y - 1]); x--; y--; }
  return ops.reverse();
}

/**
 * @param {string|null} beforeText
 * @param {string|null} afterText
 * @returns {{additions:number, deletions:number, hunks:{beforeStart:number,beforeCount:number,afterStart:number,afterCount:number,added:string[],deleted:string[]}[], approximate:boolean}}
 *   Line numbers are 1-based. A hunk with beforeCount 0 is a pure insertion after line beforeStart-1.
 */
export function diffLines(beforeText, afterText, { maxEditDistance = MAX_EDIT_DISTANCE } = {}) {
  const a = splitLines(beforeText); const b = splitLines(afterText);
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const am = a.slice(pre, a.length - suf); const bm = b.slice(pre, b.length - suf);
  if (!am.length && !bm.length) return { additions: 0, deletions: 0, hunks: [], approximate: false };
  let ops = am.length && bm.length ? myers(am, bm, maxEditDistance) : null;
  let approximate = false;
  if (!ops) {
    if (am.length && bm.length) approximate = true; // search bound hit: count the whole middle as replaced
    ops = [...am.map((_, i) => ['-', i, 0]), ...bm.map((_, j) => ['+', 0, j])];
  }
  const hunks = [];
  let cur = null; let ai = 0; let bi = 0;
  const flush = () => { if (cur) { hunks.push(cur); cur = null; } };
  for (const [op] of ops) {
    if (op === '=') { flush(); ai++; bi++; continue; }
    if (!cur) cur = { beforeStart: pre + ai + 1, beforeCount: 0, afterStart: pre + bi + 1, afterCount: 0, added: [], deleted: [] };
    if (op === '-') { cur.deleted.push(am[ai]); cur.beforeCount++; ai++; } else { cur.added.push(bm[bi]); cur.afterCount++; bi++; }
  }
  flush();
  const additions = hunks.reduce((s, h) => s + h.afterCount, 0);
  const deletions = hunks.reduce((s, h) => s + h.beforeCount, 0);
  return { additions, deletions, hunks, approximate };
}
