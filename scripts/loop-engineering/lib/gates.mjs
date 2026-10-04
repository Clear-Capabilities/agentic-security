// Gate wrapper: runs an argv under supervision and judges it against its
// EXPECTED exit codes. A gate that is expected to exit non-zero (a scanner run
// over a deliberately vulnerable fixture exits with a severity code) is checked
// here, explicitly; nothing is ever accepted through `|| true`, and an
// unexpected zero is as much a failure as an unexpected non-zero.
import { resolve } from 'node:path';
import { runBounded } from './proc.mjs';
import { registerOpLease } from './oplease.mjs';

export async function runGateCommand(gate, { repoRoot, logPath = null, runId = null, owned = null, leasesDir = null, env = null, graceMs = 5000 } = {}) {
  const expected = gate.expectedExitCodes || [0];
  const lease = leasesDir ? registerOpLease(leasesDir, { label: `gate ${gate.id}`, deadlineSeconds: gate.timeoutSeconds + 15 }) : null;
  try {
    const r = await runBounded({
      argv: [gate.executable, ...gate.args], cwd: resolve(repoRoot, gate.cwd), wallMs: gate.timeoutSeconds * 1000, graceMs,
      logPath, runId, owned, label: `gate:${gate.id}`, env: env || { ...process.env, NO_COLOR: '1' },
    });
    const exitedClean = r.outcome === 'exited';
    const ok = exitedClean && expected.includes(r.exitCode);
    return {
      id: gate.id, argv: [gate.executable, ...gate.args], cwd: gate.cwd, expectedExitCodes: expected,
      exitCode: r.exitCode, signal: r.signal, outcome: r.outcome, durationMs: r.durationMs, ok, log: logPath, reason: ok ? null : (r.reason || (exitedClean ? `exit ${r.exitCode}, expected ${expected.join('|')}` : r.outcome)),
      stdoutTail: r.stdoutTail, run: r,
    };
  } finally { lease?.release(); }
}
