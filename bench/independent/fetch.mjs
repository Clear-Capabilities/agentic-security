#!/usr/bin/env node
// Materialise the independent population's pre/post trees from upstream.
//
// Source is FETCHED, never vendored. This repository does not carry other
// people's code, and the manifest pins exact SHAs so a run is reproducible for
// as long as upstream keeps its history. The cache is gitignored.
//
// pre/  = the changed files at the fix commit's PARENT (still vulnerable)
// post/ = the same files at the FIX COMMIT (fixed upstream)
//
// A file that cannot be fetched leaves the entry INCOMPLETE, which the runner
// then reports as UNSCORED. It is never silently treated as an empty file:
// scanning an empty tree yields no findings, which would score as a miss and
// blame the engine for a network failure.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CACHE_DIR = path.join(HERE, 'cache');
const MANIFEST = path.join(HERE, 'manifest.json');
const FORGE_CLI = 'gh';

/** Raw file content at a ref, or null. */
function fileAt(repo, ref, file) {
  const r = spawnSync(FORGE_CLI, [
    'api', `repos/${repo}/contents/${file}?ref=${ref}`,
    '--jq', '.content',
  ], { encoding: 'utf8', shell: false, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) return null;
  const b64 = String(r.stdout || '').trim();
  if (!b64) return null;
  try { return Buffer.from(b64, 'base64').toString('utf8'); } catch { return null; }
}

function writeFile(root, rel, content) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

export function entryDir(id) { return path.join(CACHE_DIR, id); }

/** True when both trees are present and non-empty for every listed file. */
export function entryComplete(entry) {
  const dir = entryDir(entry.id);
  for (const side of ['pre', 'post']) {
    for (const f of entry.files) {
      const p = path.join(dir, side, f);
      if (!fs.existsSync(p) || fs.statSync(p).size === 0) return false;
    }
  }
  return true;
}

async function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const force = process.argv.includes('--force');
  let done = 0, skipped = 0, failed = 0;

  for (const e of manifest.entries) {
    const dir = entryDir(e.id);
    if (!force && entryComplete(e)) { skipped++; continue; }

    let ok = true;
    for (const f of e.files) {
      const pre = fileAt(e.repo, e.parentCommit, f);
      const post = fileAt(e.repo, e.fixCommit, f);
      // Both sides or neither. A half-materialised entry would be scored on a
      // tree that does not correspond to the labelled commit pair.
      if (pre === null || post === null) { ok = false; break; }
      writeFile(path.join(dir, 'pre'), f, pre);
      writeFile(path.join(dir, 'post'), f, post);
    }

    if (ok) { done++; process.stderr.write(`  ✓ ${e.id}  ${e.repo}\n`); }
    else {
      failed++;
      fs.rmSync(dir, { recursive: true, force: true }); // never leave a partial tree
      process.stderr.write(`  ✗ ${e.id}  ${e.repo} — could not fetch every file; entry will be UNSCORED\n`);
    }
  }

  process.stderr.write(`\nfetched ${done}, already present ${skipped}, unfetchable ${failed} ` +
    `(of ${manifest.entries.length} total)\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { process.stderr.write(`fetch failed: ${e.message}\n`); process.exit(1); });
}
