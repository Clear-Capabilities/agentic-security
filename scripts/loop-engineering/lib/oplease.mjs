// Registered bounded operations (compile / test / VM jobs). A quiet but
// registered operation is NOT a hang: the idle detector exempts it. The lease
// carries a deadline fixed at registration (never renewable), and it only
// counts while its owning process is alive, so a crashed operation cannot keep
// a worker immortal.
import { readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { atomicWriteJson, readJson, randomId, nowIso } from './util.mjs';
import { identityMatches, startTimeOf } from './procscan.mjs';

export const MAX_LEASE_SECONDS = 1800; // PRD 6.2: VM operations are the longest allowed

export function registerOpLease(dir, { label, deadlineSeconds, pid = process.pid }) {
  if (!Number.isFinite(deadlineSeconds) || deadlineSeconds <= 0) throw new RangeError('lease deadline must be a finite positive number of seconds');
  const secs = Math.min(deadlineSeconds, MAX_LEASE_SECONDS);
  const id = `${Date.now()}-${randomId(3)}`;
  const file = join(dir, `${id}.json`);
  atomicWriteJson(file, { id, label, pid, start: startTimeOf(pid), startedAt: nowIso(), deadlineAt: Date.now() + secs * 1000, deadlineSeconds: secs });
  return { id, file, release() { try { unlinkSync(file); } catch { /* already gone */ } } };
}

export function activeOpLeases(dir, now = Date.now()) {
  let names = [];
  try { names = readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  const live = [];
  for (const n of names) {
    const f = join(dir, n);
    const l = readJson(f, null);
    if (!l) continue;
    if (l.deadlineAt <= now || !identityMatches(l.pid, l.start)) { try { unlinkSync(f); } catch { /* raced */ } continue; }
    live.push(l);
  }
  return live;
}
