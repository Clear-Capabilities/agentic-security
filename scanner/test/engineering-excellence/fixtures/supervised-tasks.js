// Analyzer stand-ins for e6-05: one well-behaved, and the ways an analyzer can go wrong. Run in a child process by the supervisor.
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';

export function good(name) { return [{ id: `f-${name}`, severity: 'high', file: `${name}.js`, line: 1, vuln: 'x', cwe: 'CWE-1', description: 'd', remediation: 'r', parser: 'T', family: 'x' }]; }
export async function slowGood(ms, name) { await new Promise((r) => setTimeout(r, ms)); return good(name); }
export function infiniteLoop() { for (;;) { /* never returns */ } }
export function memoryHog() { const keep = []; for (;;) keep.push(new Array(1e6).fill('x'.repeat(64))); }
export function throws() { throw new Error('analyzer exploded'); }
export function hardExit() { process.exit(7); }
export function bigResult() { return { findings: [], pad: 'x'.repeat(2 * 1024 * 1024) }; }
// forks a long-lived grandchild in the same process group, records its pid, then hangs
export function forkThenHang(pidFile) {
  const c = spawn('sleep', ['120'], { stdio: 'ignore' });
  fs.writeFileSync(pidFile, String(c.pid));
  for (;;) { /* hang */ }
}
export function busyCpu() { let x = 0; for (;;) x += Math.sqrt(x + 1); }
