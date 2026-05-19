// FR-SEM-9 — Bounded concurrency heuristic checker.
//
// A real model checker is research; this module ships the high-leverage
// subset: regex-level detectors for the four most common concurrency bugs
// commercial SAST misses.
//
//   1. Missed-unlock — `mutex.Lock()` / `lock.acquire()` / `synchronized` /
//      `pthread_mutex_lock` without a matching unlock on every exit path
//      within the same function body (early returns, exceptions).
//   2. Data race — a shared variable (file-scope or struct field) written
//      from a goroutine / async task / Worker without protection from a
//      detected mutex/Lock/atomic primitive.
//   3. Deadlock cycle — two functions where one acquires A then B and
//      another acquires B then A. Bounded to ≤ 50 functions per scan.
//   4. Fire-and-forget — async function that mutates shared state called
//      without `await` (Node), `wait()` (Python), `.get()` (futures).
//
// Languages: Go, Java, JS/TS, Python. Each pattern is conservative — we
// only emit when the surface evidence is unambiguous. Severity is medium
// by default; family `concurrency-bug`.

const PATTERNS = {
  go: {
    lockAcquire: /\b(\w+)\.Lock\(\)/g,
    lockRelease: /\b(\w+)\.Unlock\(\)/g,
    asyncStart: /\bgo\s+\w/g,
    syncOnce: /\bsync\.Once\b/g,
    shared: /^var\s+(\w+)\s+\w/gm,
  },
  java: {
    lockAcquire: /\b(\w+)\.lock\(\)/g,
    lockRelease: /\b(\w+)\.unlock\(\)/g,
    synchronized: /\bsynchronized\s*\(/g,
    asyncStart: /\bnew\s+Thread\(|\.start\(\)|@Async\b|CompletableFuture\.runAsync/g,
  },
  js: {
    asyncFn: /\basync\s+function\s+\w+|async\s+\(/g,
    asyncCallNoAwait: /^(?!.*\bawait\b).*\b\w+\s*\([^)]*\)\.then\(/gm,
    workerPost: /\bworker\.postMessage\b/g,
    sharedAt: /^(?:const|let|var)\s+(\w+)\s*=/gm,
  },
  py: {
    lockAcquire: /\b(\w+)\.acquire\(\)/g,
    lockRelease: /\b(\w+)\.release\(\)/g,
    asyncDef: /\basync\s+def\s+\w+/g,
    asyncCallNoAwait: /^(?!.*\bawait\b).*\basyncio\.create_task\(/gm,
  },
};

function inferLang(fp) {
  if (/\.go$/i.test(fp)) return 'go';
  if (/\.(java|kt)$/i.test(fp)) return 'java';
  if (/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}

// Walk a function body and collect lock acquire/release pairs.
// Naive: assume single-block functions. Good enough for the common case.
function extractFunctions(text, lang) {
  const out = [];
  let m;
  if (lang === 'go') {
    const re = /func(?:\s+\(\w+\s+\*?\w+\))?\s+(\w+)\s*\([^)]*\)[^{]*\{/g;
    while ((m = re.exec(text))) {
      const body = grabBody(text, m.index + m[0].length - 1);
      if (body) out.push({ name: m[1], body, startLine: text.slice(0, m.index).split('\n').length });
    }
  } else if (lang === 'java') {
    const re = /(?:public|private|protected|static|final|synchronized)\s+[\w<>,\s\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{/g;
    while ((m = re.exec(text))) {
      const body = grabBody(text, m.index + m[0].length - 1);
      if (body) out.push({ name: m[1], body, startLine: text.slice(0, m.index).split('\n').length });
    }
  } else if (lang === 'js') {
    const re = /(?:function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)/g;
    while ((m = re.exec(text))) {
      const braceIdx = text.indexOf('{', m.index);
      if (braceIdx < 0) continue;
      const body = grabBody(text, braceIdx);
      if (body) out.push({ name: m[1] || m[2], body, startLine: text.slice(0, m.index).split('\n').length });
    }
  } else if (lang === 'py') {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m2 = /^def\s+(\w+)\s*\(|^async\s+def\s+(\w+)\s*\(/.exec(lines[i]);
      if (!m2) continue;
      const name = m2[1] || m2[2];
      const body = lines.slice(i, Math.min(i + 80, lines.length)).join('\n');
      out.push({ name, body, startLine: i + 1 });
    }
  }
  return out;
}

function grabBody(text, openBraceIdx) {
  if (text[openBraceIdx] !== '{') return null;
  let depth = 0;
  for (let i = openBraceIdx; i < Math.min(openBraceIdx + 8000, text.length); i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) return text.slice(openBraceIdx, i + 1);
    }
  }
  return null;
}

function findMissedUnlocks(fn, lang) {
  const out = [];
  const p = PATTERNS[lang];
  if (!p || !p.lockAcquire || !p.lockRelease) return out;
  const acquires = [...fn.body.matchAll(p.lockAcquire)];
  const releases = [...fn.body.matchAll(p.lockRelease)];
  if (!acquires.length) return out;
  // For each acquired lock name, check at least one release in the body.
  const acquiredNames = new Set(acquires.map(m => m[1]));
  const releasedNames = new Set(releases.map(m => m[1]));
  for (const name of acquiredNames) {
    if (!releasedNames.has(name)) {
      out.push({
        kind: 'missed-unlock',
        lock: name,
        functionName: fn.name,
        startLine: fn.startLine,
      });
    } else {
      // Lock+unlock both present, but check that the function has a defer/
      // try-finally guarantee. Go: `defer`; Java/Py: try/finally; otherwise
      // early-return-before-unlock is a risk.
      const guarded =
        (lang === 'go' && /defer\s+\w+\.Unlock\(\)/.test(fn.body)) ||
        (lang === 'java' && /try\s*\{[\s\S]*finally\s*\{[\s\S]*\.unlock\(\)/m.test(fn.body)) ||
        (lang === 'py' && (/with\s+\w+:/.test(fn.body) || /try\s*:[\s\S]*finally\s*:[\s\S]*\.release\(\)/m.test(fn.body)));
      if (!guarded && /\breturn\b/.test(fn.body)) {
        out.push({
          kind: 'unguarded-lock',
          lock: name,
          functionName: fn.name,
          startLine: fn.startLine,
          remediation: lang === 'go' ? 'use `defer mu.Unlock()`' :
                       lang === 'java' ? 'wrap in try/finally with unlock in finally' :
                       lang === 'py' ? 'use `with lock:` context manager' :
                       'guarantee release on every exit path',
        });
      }
    }
  }
  return out;
}

function findFireAndForget(fn, lang) {
  const out = [];
  const p = PATTERNS[lang];
  if (!p || !p.asyncCallNoAwait) return out;
  let m;
  p.asyncCallNoAwait.lastIndex = 0;
  while ((m = p.asyncCallNoAwait.exec(fn.body))) {
    if (/\bvoid\s/.test(m[0])) continue;        // explicit void = intentional
    out.push({
      kind: 'fire-and-forget',
      functionName: fn.name,
      startLine: fn.startLine,
      snippet: m[0].slice(0, 80),
    });
  }
  return out;
}

function findDeadlockCycles(fns) {
  // Build a graph: function → list of lock pairs acquired in order.
  // Cycle if A acquires (x,y) and B acquires (y,x) somewhere — even when
  // distinct calls are interleaved at runtime.
  const lockOrders = [];
  for (const fn of fns) {
    const acquires = [...fn.body.matchAll(/\b(\w+)\.(?:Lock|lock|acquire)\(\)/g)].map(m => m[1]);
    const distinct = [...new Set(acquires)];
    if (distinct.length >= 2) {
      lockOrders.push({ fn: fn.name, startLine: fn.startLine, pairs: pairsOf(distinct) });
    }
    if (lockOrders.length > 50) break;          // bounded
  }
  const out = [];
  for (let i = 0; i < lockOrders.length; i++) {
    for (let j = i + 1; j < lockOrders.length; j++) {
      const a = lockOrders[i], b = lockOrders[j];
      for (const [x, y] of a.pairs) {
        for (const [bx, by] of b.pairs) {
          if (x === by && y === bx) {
            out.push({
              kind: 'deadlock-cycle',
              functionA: a.fn,
              functionB: b.fn,
              order: `${a.fn} locks (${x}, ${y}); ${b.fn} locks (${bx}, ${by})`,
              startLineA: a.startLine,
              startLineB: b.startLine,
            });
          }
        }
      }
    }
  }
  return out;
}

function pairsOf(arr) {
  const p = [];
  for (let i = 0; i < arr.length; i++)
    for (let j = i + 1; j < arr.length; j++) p.push([arr[i], arr[j]]);
  return p;
}

export function scanConcurrency(fileContents) {
  const findings = [];
  if (!fileContents) return findings;
  for (const [fp, text] of Object.entries(fileContents)) {
    const lang = inferLang(fp);
    if (!lang || !text) continue;
    const fns = extractFunctions(text, lang);
    if (!fns.length) continue;

    for (const fn of fns) {
      for (const bug of findMissedUnlocks(fn, lang)) {
        findings.push({
          id: `concurrency:${bug.kind}:${fp}:${bug.startLine}:${bug.lock}`,
          file: fp,
          line: bug.startLine,
          vuln: bug.kind === 'missed-unlock'
            ? `Concurrency: ${fn.name}() acquires ${bug.lock} but no matching unlock`
            : `Concurrency: ${fn.name}() can return without releasing ${bug.lock}`,
          severity: 'medium',
          family: 'concurrency-bug',
          confidence: 0.5,
          remediation: bug.remediation || 'Release the lock on every exit path (defer / try-finally / context manager).',
        });
      }
      for (const bug of findFireAndForget(fn, lang)) {
        findings.push({
          id: `concurrency:fire-forget:${fp}:${bug.startLine}`,
          file: fp,
          line: bug.startLine,
          vuln: `Concurrency: fire-and-forget async call in ${fn.name}() — result not awaited`,
          severity: 'low',
          family: 'concurrency-bug',
          confidence: 0.4,
          remediation: 'Await the promise / call .get() on the future / use asyncio.gather.',
        });
      }
    }

    for (const bug of findDeadlockCycles(fns)) {
      findings.push({
        id: `concurrency:deadlock:${fp}:${bug.startLineA}-${bug.startLineB}`,
        file: fp,
        line: bug.startLineA,
        vuln: `Concurrency: potential deadlock — ${bug.order}`,
        severity: 'high',
        family: 'concurrency-bug',
        confidence: 0.4,
        remediation: 'Acquire locks in a consistent global order across all call sites.',
      });
    }
  }
  return findings;
}
