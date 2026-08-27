import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

function cacheDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'provenance', 'cache');
}

function keyPath(scanRoot, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return path.join(cacheDir(scanRoot), hash + '.json');
}

export function makeCacheKey({ repoHead, stableId, detectorVersion, historyBoundary, mode }) {
  return [repoHead || '', stableId || '', detectorVersion || '', historyBoundary || '', mode || ''].join('|');
}

export function cacheGet(scanRoot, key) {
  try {
    const p = keyPath(scanRoot, key);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

export function cacheSet(scanRoot, key, value) {
  try {
    fs.mkdirSync(cacheDir(scanRoot), { recursive: true });
    fs.writeFileSync(keyPath(scanRoot, key), JSON.stringify(value));
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
