// `process.stdout.write(body)` followed by `process.exit(code)` truncates.
//
// When stdout is a PIPE (any `> file`, `| jq`, or CI capture — i.e. every
// non-interactive use), Node's stdout is asynchronous. `process.exit()` does
// not flush it, so whatever has not reached the OS yet is discarded at the
// pipe buffer boundary — 64 KiB on macOS and Linux.
//
// The CLI dispatches every command as `process.exit(await cmdX(args))`, so any
// payload over 64 KiB was silently cut mid-token. `scan --format sarif` is the
// primary CI integration path: `agentic-security scan . --format sarif >
// results.sarif` produced a file that is not valid JSON for any project big
// enough to matter, with exit status 0/3 and no error message. A truncated
// SARIF is worse than no SARIF — the uploader reports a parse error far from
// the cause, or silently ingests a partial finding set.
//
// These tests exercise the real CLI through a real pipe. They are deliberately
// end-to-end: the bug is invisible in-process (a TTY and a file both flush
// synchronously), so only a piped subprocess can catch it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'bin', 'agentic-security.js');
const SCAN_TARGET = path.join(HERE, '..', 'src', 'posture');
const PIPE_BUFFER = 64 * 1024;

function runPiped(...argv) {
  return spawnSync(process.execPath, [CLI, ...argv], {
    cwd: path.join(HERE, '..'),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024, // must exceed the payload, or WE truncate it
  });
}

test('SARIF over the pipe buffer survives to stdout intact', () => {
  const r = runPiped('scan', SCAN_TARGET, '--format', 'sarif');
  const bytes = Buffer.byteLength(r.stdout || '');

  assert.ok(
    bytes > PIPE_BUFFER,
    `fixture must exceed the ${PIPE_BUFFER}-byte pipe buffer to prove anything, got ${bytes}`,
  );
  assert.doesNotThrow(
    () => JSON.parse(r.stdout),
    `SARIF truncated at ${bytes} bytes — invalid JSON reached stdout`,
  );
});

test('the emitted SARIF is complete, not merely parseable', () => {
  // A truncation that happened to land on a closing brace would still parse.
  // Assert the document's own terminal structure is present.
  const r = runPiped('scan', SCAN_TARGET, '--format', 'sarif');
  const doc = JSON.parse(r.stdout);
  assert.ok(Array.isArray(doc.runs) && doc.runs.length > 0, 'SARIF must carry its runs array');
  assert.ok(Array.isArray(doc.runs[0].results), 'SARIF run must carry its results array');
});

test('JSON format over the pipe buffer survives to stdout intact', () => {
  const r = runPiped('scan', SCAN_TARGET, '--format', 'json');
  const bytes = Buffer.byteLength(r.stdout || '');
  assert.ok(bytes > PIPE_BUFFER, `expected a payload over the pipe buffer, got ${bytes}`);
  assert.doesNotThrow(() => JSON.parse(r.stdout), `JSON truncated at ${bytes} bytes`);
});
