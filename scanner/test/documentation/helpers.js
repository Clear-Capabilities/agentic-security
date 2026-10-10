// Shared helpers for the documentation suites. Not a test file.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SCANNER = path.resolve(HERE, '..', '..');
export const REPO = path.resolve(SCANNER, '..');
export const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

/**
 * Run a command the way a documentation reader does and the way CI does: no terminal (stdin is closed, so a prompt would fail at once
 * rather than wait), a hard timeout, output captured. A command that hangs is killed and reported as a timeout, which fails its test.
 */
export function run(file, args = [], { env = {}, cwd = SCANNER, timeout = 120000 } = {}) {
  const r = spawnSync(file, args, { cwd, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
  return { status: r.status, signal: r.signal, timedOut: r.error?.code === 'ETIMEDOUT', stdout: r.stdout ?? '', stderr: r.stderr ?? '', text: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}
export const node = (script, args = [], opts = {}) => run(process.execPath, [script, ...args], opts);
export const script = (rel, args = [], opts = {}) => node(path.join(REPO, rel), args, { cwd: REPO, ...opts });
export const cli = (args = [], opts = {}) => node(path.join(SCANNER, 'bin', 'agentic-security.js'), args, opts);

/** The ```text blocks of a page, as arrays of lines. */
export function textBlocks(md) {
  const out = [];
  let cur = null;
  for (const line of md.split('\n')) {
    const m = /^\s*```(\S*)/.exec(line);
    if (m) { if (cur === null) cur = m[1] === 'text' ? [] : undefined; else { if (Array.isArray(cur)) out.push(cur); cur = null; } continue; }
    if (Array.isArray(cur)) cur.push(line);
  }
  return out;
}

/** The first text block with a line that starts with `prefix`. */
export function blockWith(md, prefix) {
  const b = textBlocks(md).find((lines) => lines.some((l) => l.trim().startsWith(prefix)));
  assert_(b, `no text block starts a line with "${prefix}"`);
  return b;
}
function assert_(ok, msg) { if (!ok) throw new Error(msg); }

/** Run-specific tokens (content hashes, ids, durations) are masked so a documented output can be compared with a fresh one. */
export function norm(line) {
  return line.trim().replace(/^\|\s*/, '')
    .replace(/run-\d{8}T\d{6}Z-[0-9a-f]+/g, 'run-#')
    .replace(/\b(PID:?|pid) ?\d+/g, '$1 #')
    .replace(/127\.0\.0\.1:\d+/g, '127.0.0.1:#')
    .replace(/as of \d+/g, 'as of #')
    .replace(/\b(rpl|vrec|wu|pplan):[0-9a-f]{6,}/g, '$1:#')
    .replace(/sha256:[0-9a-f]+/g, 'sha256:#')
    .replace(/\b[0-9a-f]{12,}\b/g, '#')
    .replace(/#\d+\.\d+/g, '#N.N')
    .replace(/\b\d+ ?ms\b/g, 'N ms')
    .replace(/\bin \d+ms;/g, 'in N ms;')
    .replace(/\s+/g, ' ');
}

/** The lines of a documented block that a real run did not print. An empty list means the page quotes the run faithfully. */
export function missingFrom(blockLines, actualText, { ignore = () => false } = {}) {
  const have = new Set(actualText.split('\n').map(norm));
  return blockLines.map(norm).filter((l) => l && !ignore(l) && !have.has(l));
}
