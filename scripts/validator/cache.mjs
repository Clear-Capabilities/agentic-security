#!/usr/bin/env node
// Verdict cache for /validate-findings.
// Keyed on a hash of (finding.id, file hash, scanner version).
// Persisted under .agentic-security/poc-cache/<key>.json.
//
// Usage:
//   cache.js read <finding-id>            → prints cached verdict JSON or "MISS"
//   cache.js write <finding-id> <verdict-json>  → writes verdict to cache
//   cache.js clear                         → wipes the entire cache

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const CACHE_DIR = path.join(process.cwd(), '.agentic-security', 'poc-cache');

function ensureDir() { fs.mkdirSync(CACHE_DIR, { recursive: true }); }

function findingFromScan(id) {
  const scanPath = path.join(process.cwd(), '.agentic-security', 'last-scan.json');
  if (!fs.existsSync(scanPath)) return null;
  try {
    const scan = JSON.parse(fs.readFileSync(scanPath, 'utf8'));
    const findings = [...(scan.findings || []), ...(scan.logicVulns || []), ...(scan.supplyChain || [])];
    return findings.find(f => f.id === id) || null;
  } catch { return null; }
}

function fileHash(absPath) {
  try {
    const buf = fs.readFileSync(absPath);
    return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 12);
  } catch { return 'nofile'; }
}

function scannerVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
    return pkg.version || 'unknown';
  } catch { return 'unknown'; }
}

function cacheKey(findingId) {
  const f = findingFromScan(findingId);
  const filePath = f?.file || f?.sink?.file || '';
  const absFile = filePath ? path.resolve(process.cwd(), filePath) : '';
  const fh = absFile ? fileHash(absFile) : 'nofile';
  const sv = scannerVersion();
  const key = `${findingId}::${fh}::${sv}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 24);
}

function read(id) {
  const key = cacheKey(id);
  const p = path.join(CACHE_DIR, key + '.json');
  if (!fs.existsSync(p)) { process.stdout.write('MISS'); process.exit(0); }
  process.stdout.write(fs.readFileSync(p, 'utf8'));
}

function write(id, verdictJson) {
  ensureDir();
  const key = cacheKey(id);
  const p = path.join(CACHE_DIR, key + '.json');
  try { JSON.parse(verdictJson); } catch (e) { console.error('Invalid verdict JSON:', e.message); process.exit(1); }
  fs.writeFileSync(p, verdictJson);
  process.stdout.write(`WROTE ${key}\n`);
}

function clear() {
  if (fs.existsSync(CACHE_DIR)) fs.rmSync(CACHE_DIR, { recursive: true, force: true });
  process.stdout.write('CLEARED\n');
}

const [, , cmd, id, verdict] = process.argv;
if (cmd === 'read' && id) read(id);
else if (cmd === 'write' && id && verdict) write(id, verdict);
else if (cmd === 'clear') clear();
else {
  console.error('Usage: cache.js read <id> | write <id> <verdict-json> | clear');
  process.exit(2);
}
