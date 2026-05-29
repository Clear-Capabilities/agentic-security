---
description: Continuously scan as you edit. Surfaces a one-line risk delta after each change.
argument-hint: "[--stop] [--status]"
---

# /watch

Start a continuous incremental scan in the background. After every file change (debounced 350ms) re-runs the affected slice of the scan and writes a one-line risk delta to `.agentic-security/watch-status.md`.

The Claude Code statusline (or just `cat .agentic-security/watch-status.md`) shows the current state without re-running anything expensive.

## Modes

- `/watch` — start watching the current project
- `/watch --status` — show the latest delta
- `/watch --stop` — stop the background watcher

## Output

`.agentic-security/watch-status.md`:
```
# Watch status — 14:32:08 UTC

agentic-security: 🛑 +1 crit · ⚠️  +2 high

## New findings

- **[CRITICAL]** SQL injection — `src/api/login.js:42`
- **[HIGH]** Missing CSRF middleware — `src/routes/profile.js:15`
- **[HIGH]** XSS via dangerouslySetInnerHTML — `src/components/Bio.tsx:8`
```

## Implementation

```js
import { watchProject, computeDelta, persistStatus } from '@clear-capabilities/agentic-security-scanner/posture/watch-mode.js';
import { runScan } from '@clear-capabilities/agentic-security-scanner/runScan';

let prevFindings = (await runScan(cwd)).scan.findings || [];
const handle = await watchProject(cwd, async (changedFiles) => {
  const { scan } = await runScan(cwd, { incremental: true, only: changedFiles });
  const delta = computeDelta(prevFindings, scan.findings || []);
  persistStatus(cwd, delta);
  prevFindings = scan.findings;
});
// handle.stop() to terminate.
```

## Performance

- Incremental scan reuses the dataflow cache (`dataflow/incremental-cache.js`)
- Per-file scan budget: ~5 seconds
- Debounces bursts (e.g. `npm run lint --fix` editing 50 files at once)

## Opt-out

`AGENTIC_SECURITY_NO_WATCH=1` disables watch mode entirely (useful in CI).
