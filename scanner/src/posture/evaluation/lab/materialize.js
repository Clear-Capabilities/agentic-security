// Turn a dataset entry's workspace reference into a directory of files (PRD 6, requirement 3: vulnerable commit -> fixing commit).
// Two sources: a folder inside the manifest's own directory, or a revision of a LOCAL git repository read with `git archive`
// (so no checkout, no hooks and no working tree are involved) and unpacked through the hardened tar reader. Nothing is fetched
// from the network, a moving ref is refused at validation time, and every limit is a typed failure rather than a truncation.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { readTarEntries, TarSafetyError } from '../../../artifact/safe-tar.js';
import { resolveInside } from './dataset.js';

const MATERIALIZE_LIMITS = Object.freeze({ gitTimeoutMs: 120_000, maxArchiveBytes: 512 * 1024 * 1024, maxFiles: 50_000, maxFileBytes: 16 * 1024 * 1024 });

export function materializeEntry(entry, { baseDir, destDir, limits = MATERIALIZE_LIMITS } = {}) {
  fs.rmSync(destDir, { recursive: true, force: true });
  fs.mkdirSync(destDir, { recursive: true });
  const ws = entry.workspace;
  if (ws.dir !== undefined) {
    const src = resolveInside(baseDir, ws.dir);
    if (!src || !fs.statSync(src).isDirectory()) return { ok: false, reason: 'workspace directory is missing or outside the manifest folder' };
    fs.cpSync(src, destDir, { recursive: true, dereference: false, filter: (s) => !['.git', 'node_modules'].includes(path.basename(s)) });
    return { ok: true, source: 'directory' };
  }
  const repo = resolveInside(baseDir, ws.git.repo) ?? (path.isAbsolute(ws.git.repo) && fs.existsSync(ws.git.repo) ? fs.realpathSync(ws.git.repo) : null);
  if (!repo) return { ok: false, reason: 'git repository not found' };
  const r = spawnSync('git', ['-C', repo, 'archive', '--format=tar', ws.git.rev], { timeout: limits.gitTimeoutMs, killSignal: 'SIGKILL', maxBuffer: limits.maxArchiveBytes, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' } });
  if (r.error) return { ok: false, reason: r.error.code === 'ETIMEDOUT' ? 'git archive timed out' : r.error.code === 'ENOBUFS' ? 'archive exceeds the size limit' : `git archive failed: ${r.error.code || r.error.message}` };
  if (r.status !== 0) return { ok: false, reason: `git archive failed: ${String(r.stderr).split('\n')[0].slice(0, 160)}` };
  let files = 0;
  try {
    for (const e of readTarEntries(r.stdout)) {
      if (e.unsafe) return { ok: false, reason: `unsafe path in the archive: ${String(e.name).slice(0, 80)}` };
      if (e.typeflag !== '0' && e.typeflag !== '\0') continue; // directories are implied; links and devices are never created
      if (++files > limits.maxFiles) return { ok: false, reason: `more than ${limits.maxFiles} files` };
      if (e.size > limits.maxFileBytes) return { ok: false, reason: `a file exceeds ${limits.maxFileBytes} bytes` };
      const target = path.resolve(destDir, e.name);
      if (target !== destDir && !target.startsWith(destDir + path.sep)) return { ok: false, reason: 'archive path escapes the workspace' };
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, e.data);
    }
  } catch (err) {
    return { ok: false, reason: err instanceof TarSafetyError ? `archive refused: ${err.message}` : `archive unreadable: ${err.message}` };
  }
  return { ok: true, source: 'git', files };
}
