// Shared primitives for the loop controller: hashing, atomic writes, redaction,
// and a deadline clock that cannot be extended by machine sleep.
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, existsSync, appendFileSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
export const randomId = (n = 4) => randomBytes(n).toString('hex');
export const nowIso = () => new Date().toISOString();
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Key-sorted JSON so a digest does not depend on property insertion order.
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}

// Write-then-rename so a reader (status, dashboard, a crashed-controller
// recovery) never observes a half-written file.
export function atomicWriteFile(path, data, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomId(3)}.tmp`;
  const fd = openSync(tmp, 'w', mode);
  try { writeSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}
export const atomicWriteJson = (path, obj) => atomicWriteFile(path, JSON.stringify(obj, null, 2) + '\n');

export function readJson(path, fallback = null) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return fallback; }
}
export const fileExists = (p) => { try { return existsSync(p); } catch { return false; } };
export function fileSize(p) { try { return statSync(p).size; } catch { return -1; } }

export function appendJsonl(path, obj) {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(obj) + '\n', { mode: 0o600 });
}

// Redaction for anything that reaches a log tail, event stream or dashboard.
const REDACTIONS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[REDACTED:private-key]'],
  [/\bsk-ant-[A-Za-z0-9_-]{8,}/g, '[REDACTED:api-key]'],
  [/\bsk-[A-Za-z0-9]{20,}/g, '[REDACTED:api-key]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, '[REDACTED:github-token]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED:aws-key]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, 'Bearer [REDACTED]'],
  [/\b(authorization|x-api-key)\s*[:=]\s*\S+/gi, '$1: [REDACTED]'],
  [/\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*\S+/g, '$1=[REDACTED]'],
  [/\b((?:secret|token|password|passwd|api[_-]?key)["']?\s*[:=]\s*["']?)[^\s"',}]{6,}/gi, '$1[REDACTED]'],
  [/\b(\w+:\/\/)([^\s/:@]+):([^\s/@]+)@/g, '$1$2:[REDACTED]@'],
];
export function redact(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  for (const [re, rep] of REDACTIONS) out = out.replace(re, rep);
  return out;
}
export function redactDeep(v) {
  if (typeof v === 'string') return redact(v);
  if (Array.isArray(v)) return v.map(redactDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactDeep(x)]));
  return v;
}

// A Deadline measures elapsed time on BOTH clocks and reports the larger.
// The monotonic clock is immune to wall-clock edits but pauses during machine
// sleep on some platforms; the wall clock sees sleep but can be edited. Taking
// the max means sleep can never silently extend a deadline (PRD 9.3), and the
// cost is that a forward clock jump ends a deadline early, which is the safe
// direction.
export class Deadline {
  constructor(ms) {
    this.ms = ms;
    this.startMono = performance.now();
    this.startWall = Date.now();
  }
  elapsed() { return Math.max(performance.now() - this.startMono, Date.now() - this.startWall); }
  remaining() { return this.ms - this.elapsed(); }
  expired() { return this.elapsed() >= this.ms; }
}

export function tail(str, n) {
  return str.length > n ? str.slice(str.length - n) : str;
}
