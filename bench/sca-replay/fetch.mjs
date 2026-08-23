#!/usr/bin/env node
// Materialise the SCA replay population — manifests and lockfiles only.
//
// Source is FETCHED, never vendored, and every ref in the manifest is a
// resolved commit SHA rather than a tag, because a tag can be moved and a
// benchmark whose inputs can change underneath it is not a benchmark.
//
// A file that cannot be fetched leaves the entry INCOMPLETE, which the runner
// reports as UNSCORED. It is never treated as an empty file: an empty lockfile
// yields no components, which would score as a total miss and blame the engine
// for a network failure. That doctrine is inherited verbatim from
// bench/independent, where it was learned the expensive way.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CACHE_DIR = path.join(HERE, 'cache');
const MANIFEST = path.join(HERE, 'manifest.json');
const FORGE_CLI = 'gh';

export function readManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
}

export function entryDir(id) { return path.join(CACHE_DIR, id); }

export function entryComplete(entry) {
  const dir = entryDir(entry.id);
  for (const f of entry.files) {
    const p = path.join(dir, f);
    if (!fs.existsSync(p) || fs.statSync(p).size === 0) return false;
  }
  // A withSource entry is not complete on its lockfiles alone: reachability
  // cannot be scored without source, and treating it as done would silently
  // reproduce the 0-demotions-everywhere result that motivated fetching it.
  if (entry.withSource && !fs.existsSync(path.join(dir, 'src-tree'))) return false;
  return true;
}

// Lockfiles routinely exceed the 1 MB the contents API will inline, and the
// API then returns an empty `content` with no error. Falling back to the raw
// host is not an optimisation — without it, next.js and kibana-sized lockfiles
// silently materialise as empty files, which is exactly the failure mode the
// header warns about.
function fileAt(repo, ref, file) {
  const r = spawnSync(FORGE_CLI, [
    'api', `repos/${repo}/contents/${file}?ref=${ref}`, '--jq', '.content',
  ], { encoding: 'utf8', shell: false, maxBuffer: 128 * 1024 * 1024 });
  if (r.status === 0) {
    const b64 = String(r.stdout || '').trim();
    if (b64) {
      try {
        const out = Buffer.from(b64, 'base64').toString('utf8');
        if (out.length) return out;
      } catch { /* fall through to raw */ }
    }
  }
  const raw = spawnSync(FORGE_CLI, [
    'api', `repos/${repo}/contents/${file}?ref=${ref}`,
    '-H', 'Accept: application/vnd.github.raw',
  ], { encoding: 'utf8', shell: false, maxBuffer: 128 * 1024 * 1024 });
  if (raw.status !== 0) return null;
  const body = String(raw.stdout || '');
  return body.length ? body : null;
}

// Source extensions the reachability analysis can actually read. Everything
// else in a repository — fixtures, images, generated bundles, vendored copies —
// is weight without signal, and `node_modules`/`vendor` would make the import
// scan measure the dependency's own code rather than the project's use of it.
const SOURCE_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|py)$/i;
const SOURCE_SKIP = /(?:^|\/)(?:node_modules|vendor|dist|build|\.git|test|tests|__tests__|spec|fixtures?|examples?)(?:\/|$)/i;
const MAX_SOURCE_FILES = 1200;
const MAX_SOURCE_BYTES = 12 * 1024 * 1024;

/**
 * Fetch a repository's SOURCE at a pinned commit, as one tarball.
 *
 * One request rather than one per file: the tree API would need ~400 calls per
 * entry and this bench already spends its network budget on the advisory
 * database. Only source files are kept, so the cache stays close to the size of
 * the lockfile-only entries.
 */
function fetchSource(repo, ref, destDir) {
  const tmp = path.join(os.tmpdir(), `sca-src-${repo.replace(/[^\w]/g, '_')}-${ref.slice(0, 8)}.tar.gz`);
  const r = spawnSync(FORGE_CLI, ['api', `repos/${repo}/tarball/${ref}`], {
    encoding: 'buffer', shell: false, maxBuffer: 512 * 1024 * 1024,
  });
  if (r.status !== 0 || !r.stdout || !r.stdout.length) return 0;
  fs.writeFileSync(tmp, r.stdout);
  const listed = spawnSync('tar', ['-tzf', tmp], { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });
  if (listed.status !== 0) { fs.rmSync(tmp, { force: true }); return 0; }

  const wanted = [];
  for (const line of String(listed.stdout || '').split('\n')) {
    const rel = line.replace(/^[^/]+\//, '');          // strip the tarball's top dir
    if (!rel || !SOURCE_EXT.test(rel) || SOURCE_SKIP.test(rel)) continue;
    wanted.push(line);
    if (wanted.length >= MAX_SOURCE_FILES) break;
  }
  if (!wanted.length) { fs.rmSync(tmp, { force: true }); return 0; }

  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'sca-src-stage-'));
  const ex = spawnSync('tar', ['-xzf', tmp, '-C', stage, ...wanted], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  fs.rmSync(tmp, { force: true });
  if (ex.status !== 0) { fs.rmSync(stage, { recursive: true, force: true }); return 0; }

  let kept = 0, bytes = 0;
  const walk = (dir, base) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) { walk(abs, base); continue; }
      const rel = path.relative(base, abs).split(path.sep).slice(1).join('/');   // drop top dir
      if (!rel) continue;
      const size = fs.statSync(abs).size;
      if (bytes + size > MAX_SOURCE_BYTES) return;
      writeFile(path.join(destDir, 'src-tree'), rel, fs.readFileSync(abs));
      kept++; bytes += size;
    }
  };
  walk(stage, stage);
  fs.rmSync(stage, { recursive: true, force: true });
  return kept;
}

function writeFile(root, rel, content) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

async function main() {
  const manifest = readManifest();
  const force = process.argv.includes('--force');
  let done = 0, skipped = 0, failed = 0;

  for (const e of manifest.entries) {
    const dir = entryDir(e.id);
    if (!force && entryComplete(e)) { skipped++; continue; }

    let ok = true;
    for (const f of e.files) {
      const body = fileAt(e.repo, e.commit, f);
      if (body === null) { ok = false; break; }
      writeFile(dir, f, body);
    }
    // A scan needs a project marker to behave like a real project rather than
    // a loose directory of files. Every entry already carries a manifest, so
    // this only matters for the lockfile-only ones.
    if (ok) {
      done++;
      let srcNote = '';
      if (e.withSource) {
        const kept = fetchSource(e.repo, e.commit, dir);
        srcNote = kept ? `  (+${kept} source files)` : '  (SOURCE UNFETCHABLE — reachability UNSCORED for this entry)';
      }
      process.stderr.write(`  ✓ ${e.id}  ${e.repo}@${e.tag}${srcNote}\n`);
    } else {
      failed++;
      fs.rmSync(dir, { recursive: true, force: true });
      process.stderr.write(`  ✗ ${e.id}  ${e.repo}@${e.tag} — unfetchable; entry will be UNSCORED\n`);
    }
  }

  process.stderr.write(`\nfetched ${done}, already present ${skipped}, unfetchable ${failed} ` +
    `(of ${manifest.entries.length} total)\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { process.stderr.write(`fetch failed: ${e.message}\n`); process.exit(1); });
}
