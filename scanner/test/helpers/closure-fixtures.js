// Shared fixtures for the release-closure tests (REL-001, REL-002): a fake process runner for the closure plan, so the
// tests exercise the real planning, recording and judging code without running any real suite.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLOSURE_STEPS } from '../../../scripts/release-closure.mjs';

export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const PKG = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
export const COMMIT = 'a'.repeat(40);
export const TREE = 'b'.repeat(40);
export const ALL_PRESENT = { platform: 'linux', hasTool: () => true, exists: () => true, canImportHaskell: () => true };
export const NO_REMOTE_TOOLS = { platform: 'darwin', hasTool: () => false, exists: () => false, canImportHaskell: () => false };

const GOOD = 'ℹ tests 5\nℹ suites 0\nℹ pass 5\nℹ fail 0\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0\n';

/** Which closure step a spawned command belongs to. */
export function stepIdFor(cmd, args) {
  if (cmd === 'npm' && args[0] === 'run') return CLOSURE_STEPS.find((s) => s.run.type === 'npm' && s.run.script === args[1])?.id ?? null;
  if (args.includes('--test')) return CLOSURE_STEPS.find((s) => s.run.type === 'node-test')?.id ?? null;
  return null;
}

/**
 * A runner that answers git and every plan command from canned data.
 *   fail:      step ids that exit 1
 *   skipped:   step ids whose output reports skipped tests while exiting 0
 *   zero:      step ids that exit 0 having run no tests
 *   dirty:     porcelain text for `git status --porcelain`
 *   head:      sequence of commits `git rev-parse HEAD` returns (last repeats)
 */
export function fakeExec({ fail = [], skipped = [], zero = [], dirty = '', head = [COMMIT], out = [] } = {}) {
  const calls = [];
  let headN = 0;
  const exec = (cmd, args) => {
    calls.push({ cmd, args });
    const text = (s, status = 0) => ({ status, signal: null, timedOut: false, error: null, stdout: Buffer.from(s), stderr: Buffer.alloc(0) });
    if (cmd === 'git') {
      if (args[0] === 'rev-parse' && args[1] === 'HEAD') return text(`${head[Math.min(headN++, head.length - 1)]}\n`);
      if (args[0] === 'rev-parse') return text(`${TREE}\n`);
      if (args[0] === 'status') return text(dirty);
    }
    const id = stepIdFor(cmd, args);
    out.push(id);
    if (id && fail.includes(id)) return text(`${GOOD}\nfailing\n`, 1);
    if (id && skipped.includes(id)) return text(GOOD.replace('ℹ skipped 0', 'ℹ skipped 2'));
    if (id && zero.includes(id)) return text('ℹ tests 0\nℹ pass 0\nℹ fail 0\nℹ skipped 0\nℹ todo 0\n');
    return text(GOOD);
  };
  exec.calls = calls;
  return exec;
}
