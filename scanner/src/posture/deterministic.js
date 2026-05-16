// Deterministic mode + rule version lockfile.
//
// `--deterministic` makes scan output byte-stable for the same input:
//   - stable-sorts every findings array by (file, line, vuln, id)
//   - strips timing/scanId variance from meta
//   - sets AGENTIC_SECURITY_DETERMINISTIC=1 so other modules (network calls,
//     KEV cache invalidation, EPSS fetches, blast-radius timestamps) can opt
//     into deterministic behavior
//
// `agentic-security rules lock` writes .agentic-security/rules.lock.json
// pinning the active rule-pack hash + scanner version. Subsequent scans with
// `--deterministic` verify the lock matches before running.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { PACKS } from './rule-packs.js';

export const SCANNER_VERSION = '0.39.0';
const LOCK_FILE = 'rules.lock.json';

// Hash the union of pack CWE sets — stable across runs as long as PACKS is unchanged.
export function computeRulePackHash() {
  const sorted = Object.entries(PACKS)
    .map(([name, p]) => [name, [...p.cwes].sort()])
    .sort(([a], [b]) => a.localeCompare(b));
  return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex').slice(0, 16);
}

export function buildLockfile() {
  return {
    schema: 1,
    scannerVersion: SCANNER_VERSION,
    rulePackHash: computeRulePackHash(),
    rulePacks: Object.fromEntries(
      Object.entries(PACKS).map(([n, p]) => [n, { cweCount: p.cwes.length }])
    ),
    generatedAt: new Date().toISOString(),
  };
}

export function writeLockfile(scanRoot) {
  const dir = path.join(scanRoot, '.agentic-security');
  fs.mkdirSync(dir, { recursive: true });
  const fp = path.join(dir, LOCK_FILE);
  const lock = buildLockfile();
  fs.writeFileSync(fp, JSON.stringify(lock, null, 2));
  return { path: fp, lock };
}

export function readLockfile(scanRoot) {
  const fp = path.join(scanRoot, '.agentic-security', LOCK_FILE);
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

// Verify the current engine matches a previously-written lockfile.
// Returns { ok, mismatches: [...] }.
export function verifyLockfile(scanRoot) {
  const lock = readLockfile(scanRoot);
  if (!lock) return { ok: false, mismatches: ['no lockfile present'] };
  const mismatches = [];
  if (lock.scannerVersion !== SCANNER_VERSION) {
    mismatches.push(`scanner version: lock=${lock.scannerVersion} current=${SCANNER_VERSION}`);
  }
  const currentHash = computeRulePackHash();
  if (lock.rulePackHash !== currentHash) {
    mismatches.push(`rule-pack hash: lock=${lock.rulePackHash} current=${currentHash}`);
  }
  return { ok: mismatches.length === 0, mismatches };
}

// Stable-sort all findings arrays in a scan in place. Stable across runs.
function sortFn(a, b) {
  const af = (a.file || ''), bf = (b.file || '');
  if (af !== bf) return af.localeCompare(bf);
  const al = a.line || 0, bl = b.line || 0;
  if (al !== bl) return al - bl;
  const av = (a.vuln || a.title || ''), bv = (b.vuln || b.title || '');
  if (av !== bv) return av.localeCompare(bv);
  return String(a.id || '').localeCompare(String(b.id || ''));
}

export function makeDeterministic(scan, meta) {
  for (const k of ['findings', 'secrets', 'logicVulns', 'supplyChain']) {
    if (Array.isArray(scan[k])) scan[k].sort(sortFn);
  }
  if (meta) {
    meta.scanId = 'deterministic';
    meta.startedAt = '1970-01-01T00:00:00.000Z';
    meta.durationMs = 0;
    meta.deterministic = true;
  }
  return { scan, meta };
}

export function isDeterministic() {
  return process.env.AGENTIC_SECURITY_DETERMINISTIC === '1';
}
