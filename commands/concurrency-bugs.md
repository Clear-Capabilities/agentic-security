---
description: Surface concurrency-bug findings — missed unlocks, unguarded locks on early-return paths, fire-and-forget async, 2-lock deadlock cycles. Covers Go, Java, JS/TS, Python.
argument-hint: "[path]"
---

Run the scanner with the v3 concurrency-checker and show only `family: 'concurrency-bug'` findings. Useful before merging async-heavy changes.

```bash
PATH_ARG="."
for arg in "$@"; do
  [ "${arg:0:1}" != "-" ] && PATH_ARG="$arg"
done

mkdir -p .agentic-security
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json --output .agentic-security/_concurrency.json >/dev/null 2>&1 || true

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/_concurrency.json','utf8')); }
catch { console.log('Scanner did not run.'); process.exit(0); }
const items = (scan.findings || []).filter(f => f.family === 'concurrency-bug');
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33', RED='31';

console.log('');
console.log(W('Concurrency-bug findings: ' + items.length, BOLD));
console.log(W('  Coverage: Go (sync.Mutex, channels), Java (synchronized, Lock),', DIM));
console.log(W('  JS/TS (workers, promises), Python (asyncio.Lock, with)', DIM));
console.log('');

const byKind = new Map();
for (const f of items) {
  const kind = (f.id || '').split(':')[1] || 'other';
  if (!byKind.has(kind)) byKind.set(kind, []);
  byKind.get(kind).push(f);
}

for (const [kind, list] of byKind) {
  console.log(W(kind + ' (' + list.length + ')', BOLD));
  for (const f of list.slice(0, 20)) {
    const color = f.severity === 'high' ? RED : f.severity === 'medium' ? YELLOW : DIM;
    console.log('  [' + W((f.severity||'').toUpperCase(), color) + '] ' + (f.vuln||'').slice(0, 70) + '  ' + f.file + ':' + f.line);
    if (f.remediation) console.log('    ' + W('fix: ' + f.remediation, DIM));
  }
  console.log('');
}

if (!items.length) console.log(W('  ✅  No concurrency bugs detected.', '32'));
"
rm -f .agentic-security/_concurrency.json
```

## What it catches

- **Missed unlock** — `mutex.Lock()` / `lock.acquire()` / `synchronized` block without a matching unlock.
- **Unguarded lock** — lock acquired, then an early return / exception path that skips the unlock. Recommends `defer` (Go) / try-finally (Java) / `with` (Python).
- **Fire-and-forget async** — async function call whose result is not awaited (`Promise.then` without await, `asyncio.create_task` without await).
- **Deadlock cycle** — function A locks (X, Y), function B locks (Y, X). Suggests a global locking order.

## What it does NOT catch (v1)

- Cross-function data races (would need a full call-graph escape analysis).
- Goroutine + channel race conditions where the synchronization is via channels.
- Java concurrent-collection misuse beyond the basic Lock/synchronized patterns.

These are PRD Phase-5 work — a true bounded model checker. The heuristic version here is conservative and catches the common cases.

🛡  agentic-security · created by ClearCapabilities.Com
