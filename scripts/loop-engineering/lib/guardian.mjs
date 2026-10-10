// The guardian is the OUTER supervisor and the independent observer. It is a
// separate process from the controller on purpose: a dead controller cannot
// report its own death, reap its own orphans, or serve a dashboard that says
// "crashed". The guardian does all three, and keeps the dashboard up for a
// finite linger after the run ends.
import { existsSync } from 'node:fs';
import { layout, judgeLease, writeLease, appendEvent, releaseRunLock, readEvents } from './state.mjs';
import { atomicWriteJson, readJson, nowIso, sleep } from './util.mjs';
import { startTimeOf, identityMatches } from './procscan.mjs';
import { reapOwned } from './proc.mjs';
import { createDashboard } from './server.mjs';
import { buildStatus, renderStaticHtml, isTerminal } from './status.mjs';
import { buildCompletionReport } from './report.mjs';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

export async function runGuardian({ repoRoot, runId, serveSpec, lingerSeconds = 3600, pollMs = 1000 }) {
  const L = layout(repoRoot, runId);
  const myStart = startTimeOf(process.pid);
  let dash = null, serve = null;
  if (serveSpec) {
    const [host, portStr] = serveSpec.split(':');
    try {
      dash = await createDashboard({ repoRoot, runId, host, port: Number(portStr) });
      serve = { url: dash.url, host, port: dash.port, requestedPort: Number(portStr), portConflict: dash.conflict };
      appendEvent(L, 'dashboard-up', { url: dash.url, portConflict: !!dash.conflict });
    } catch (e) {
      serve = { error: `dashboard failed to start: ${e.code || e.message}`, fallback: 'status --json and status.html remain available' };
      appendEvent(L, 'dashboard-failed', { error: String(e.code || e.message) });
    }
  }
  let reaped = false;
  let deadStreak = 0;
  let endedAt = null;
  const beat = () => writeLease(L.guardianLeaseFile, { runId, pid: process.pid, start: myStart, role: 'guardian', serve });
  beat();
  const stopFile = join(L.dir, 'guardian-stop');
  for (;;) {
    beat();
    if (existsSync(stopFile)) break;
    const ctl = judgeLease(L.leaseFile);
    const state = readJson(L.stateFile, null);
    if (!state) break;
    const exited = ctl.lease?.exited === true;
    // Debounce: a crash needs several consecutive dead observations, so one
    // slow poll can never trigger a reap of a healthy controller's workers.
    deadStreak = (ctl.state === 'dead' || ctl.state === 'absent') ? deadStreak + 1 : 0;
    if (!reaped && deadStreak >= 3 && !exited && !isTerminal(state.status) && state.status !== 'starting') {
      // Controller died without a clean shutdown: reclaim everything it owned.
      const owned = readJson(L.ownedFile, { entries: [] });
      const killed = await reapOwned(owned.entries || [], runId, 2000);
      const fresh = readJson(L.stateFile, state);
      fresh.status = 'crashed';
      fresh.statusReason = `controller process died unexpectedly; guardian reclaimed ${killed.length} owned process(es)`;
      fresh.current = null;
      fresh.updatedAt = nowIso();
      for (const st of Object.values(fresh.requirements || {})) if (['running', 'verifying'].includes(st.state)) st.state = 'pending';
      atomicWriteJson(L.stateFile, fresh);
      appendEvent(L, 'crash-detected', { killed, lastHeartbeat: ctl.lease?.at || null });
      releaseRunLock(repoRoot, ctl.lease?.pid);
      atomicWriteJson(L.ownedFile, { runId, entries: [] });
      reaped = true;
    }
    if (isTerminal(readJson(L.stateFile, state).status) || reaped) {
      if (!endedAt) {
        endedAt = Date.now();
        try { const st = buildStatus(repoRoot, runId); writeFileSync(L.statusHtml, renderStaticHtml(st), { mode: 0o600 }); atomicWriteJson(L.completionReport, buildCompletionReport(st)); } catch { /* fallback only */ }
      }
      if (Date.now() - endedAt > lingerSeconds * 1000) break;
    } else endedAt = null;
    // A resumed run gets a NEW controller process; stop treating the run as reaped.
    if (reaped && ctl.state === 'live') { reaped = false; endedAt = null; }
    await sleep(pollMs);
  }
  if (dash) await dash.close();
  writeLease(L.guardianLeaseFile, { runId, pid: process.pid, start: myStart, role: 'guardian', serve, exited: true });
  appendEvent(L, 'guardian-exit', {});
  return 0;
}
export { identityMatches, readEvents };
