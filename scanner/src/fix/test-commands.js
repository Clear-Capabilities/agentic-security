// Run the project's tests against the PATCHED tree, in a throwaway copy (E3-05).
//
// verifyFix used to run the tests on the tree as it was before the patch was written, which says nothing about the patch. Here the
// patch is overlaid on a copy and the tests run there; the real tree is never touched.
//
// Runner discovery covers what the existing detector does (npm/pnpm/yarn/bun scripts, pytest, go test) plus cargo, dotnet, maven,
// gradle and rspec, and an explicit argv from the caller (`command`) which always wins. Commands are argv arrays, never a shell string.
// When the patched run fails the pristine copy is run too, so "the suite was already red" is not mistaken for "the patch broke it".
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectTestCommand } from '../posture/test-runner.js';
import { STATE_DIR_NAME } from '../posture/state-dir.js';

const MAX_COPY_BYTES = 200 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git', STATE_DIR_NAME, 'node_modules', 'target', 'dist', 'build', '.venv', '__pycache__', 'bin', 'obj']);
const DEFAULT_TIMEOUT_MS = 300_000;

const has = (root, rel) => { try { return fs.existsSync(path.join(root, rel)); } catch { return false; } };
const available = (cmd) => { try { const r = spawnSync(cmd, ['--version'], { timeout: 8000, stdio: 'ignore' }); return !(r.error && r.error.code === 'ENOENT'); } catch { return false; } };

/** @returns {{cmd:string,args:string[],kind:string}|null} */
export function discoverTestCommand(root, { available: avail = available } = {}) {
  const base = detectTestCommand(root);
  if (base) return base;
  if (has(root, 'Cargo.toml') && avail('cargo')) return { cmd: 'cargo', args: ['test', '--quiet'], kind: 'cargo' };
  try { if (fs.readdirSync(root).some((f) => /\.(sln|csproj)$/.test(f)) && avail('dotnet')) return { cmd: 'dotnet', args: ['test', '--nologo'], kind: 'dotnet' }; } catch { /* unreadable root */ }
  if (has(root, 'pom.xml') && avail('mvn')) return { cmd: 'mvn', args: ['-q', 'test'], kind: 'maven' };
  if ((has(root, 'build.gradle') || has(root, 'build.gradle.kts')) && avail('gradle')) return { cmd: 'gradle', args: ['test', '--quiet'], kind: 'gradle' };
  if ((has(root, '.rspec') || has(root, 'spec')) && has(root, 'Gemfile') && avail('bundle')) return { cmd: 'bundle', args: ['exec', 'rspec'], kind: 'rspec' };
  return null;
}

function copyTree(root, dest) {
  let bytes = 0;
  fs.cpSync(root, dest, {
    recursive: true, dereference: false, verbatimSymlinks: true,
    filter: (src) => {
      const rel = path.relative(root, src);
      if (!rel) return true;
      if (rel.split(path.sep).some((s) => SKIP_DIRS.has(s))) return false;
      try { const st = fs.lstatSync(src); if (st.isFile()) { bytes += st.size; if (bytes > MAX_COPY_BYTES) throw new Error('tree-too-large'); } } catch (e) { if (e.message === 'tree-too-large') throw e; }
      return true;
    },
  });
  // dependencies are linked, not copied: tests need them, and the copy must not be able to change them
  const nm = path.join(root, 'node_modules');
  if (fs.existsSync(nm)) { try { fs.symlinkSync(nm, path.join(dest, 'node_modules'), 'dir'); } catch { /* best effort */ } }
}

function run(cwd, cmd, args, timeoutMs) {
  const t0 = Date.now();
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: timeoutMs, env: { ...process.env, CI: '1' } });
  const durationMs = Date.now() - t0;
  if (r.error && r.error.code === 'ENOENT') return { status: 'skipped', passed: null, skipped: true, reason: `${cmd}-not-installed`, exitCode: null, timedOut: false, durationMs };
  if (r.status === null) return { status: 'failed', passed: false, skipped: false, reason: 'timed-out', exitCode: null, timedOut: true, durationMs };
  return { status: r.status === 0 ? 'passed' : 'failed', passed: r.status === 0, skipped: false, reason: r.status === 0 ? null : `exit-${r.status}`, exitCode: r.status, timedOut: false, durationMs };
}

/**
 * @param {{scanRoot:string, files:Record<string,string>, command?:string[], timeoutMs?:number}} o
 */
export function runTestsOnPatchedCopy({ scanRoot, files, command, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const spec = command && command.length ? { cmd: command[0], args: command.slice(1), kind: 'explicit' } : discoverTestCommand(scanRoot);
  if (!spec) return { status: 'skipped', passed: null, skipped: true, reason: 'no-test-command-detected', exitCode: null, timedOut: false, durationMs: 0, onPatchedTree: false };
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'patched-tests-'));
  try {
    const patched = path.join(work, 'patched');
    try { copyTree(scanRoot, patched); } catch (e) { return { status: 'skipped', passed: null, skipped: true, reason: e.message === 'tree-too-large' ? 'tree-too-large-to-copy' : `copy-failed: ${e.message}`, exitCode: null, timedOut: false, durationMs: 0, onPatchedTree: false }; }
    for (const [rel, text] of Object.entries(files || {})) {
      const abs = path.resolve(patched, rel);
      if (abs !== patched && !abs.startsWith(patched + path.sep)) return { status: 'skipped', passed: null, skipped: true, reason: 'patch-path-escapes-the-copy', exitCode: null, timedOut: false, durationMs: 0, onPatchedTree: false };
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, String(text));
    }
    const result = { ...run(patched, spec.cmd, spec.args, timeoutMs), runner: spec.kind, onPatchedTree: true, preExistingFailure: false };
    if (result.status === 'failed') {
      const pristine = path.join(work, 'pristine');
      try { copyTree(scanRoot, pristine); const base = run(pristine, spec.cmd, spec.args, timeoutMs); if (base.status === 'failed') result.preExistingFailure = true; } catch { /* attribution is best effort */ }
    }
    return result;
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
}
