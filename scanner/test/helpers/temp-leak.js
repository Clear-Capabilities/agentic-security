// Measures what a test file leaves behind in the OS temp directory.
//
// Each run gets a PRIVATE temp root (TMPDIR / TEMP / TMP point at it), so the
// measurement is exact and immune to other processes writing to the real temp
// folder at the same time. Anything still inside that root after the test
// process has exited is a leak: the test (or the code it drove) created it and
// did not remove it. The private root itself is deleted before returning.
//
// Used by test/temp-leak-guard.test.js and, from the command line, to survey
// the suite:  node test/helpers/temp-leak.js test/foo.test.js [more files...]

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function sizeOf(p) {
  let total = 0;
  const stack = [p];
  while (stack.length) {
    const cur = stack.pop();
    let st;
    try { st = fs.lstatSync(cur); } catch { continue; }
    if (st.isDirectory()) {
      try { for (const e of fs.readdirSync(cur)) stack.push(path.join(cur, e)); } catch { /* unreadable: skip */ }
    } else total += st.size;
  }
  return total;
}

/**
 * Runs one test file in a child `node --test` with a private temp root and
 * returns { file, status, leaked: [names], bytes, timedOut }.
 */
export function measureTempLeaks(file, { timeoutMs = 600_000 } = {}) {
  const abs = path.isAbsolute(file) ? file : path.join(SCANNER, file);
  // Short name and NOT realpath'd: some code under test binds a unix socket inside os.tmpdir(), and a socket
  // path is limited to ~104 bytes on macOS, so a deep private root would break those tests for the wrong reason.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lp-'));
  try {
    const env = { ...process.env, TMPDIR: root, TEMP: root, TMP: root };
    // a nested run must not think it is a sub-test of the caller
    delete env.NODE_TEST_CONTEXT;
    // Output goes to a file, not a pipe: spawnSync waits for a pipe to reach EOF, and a grandchild a test
    // deliberately leaves running (a hostile-evaluator probe, say) would hold it open and hang the measurement.
    const outFd = fs.openSync(path.join(root, '.probe-output'), 'w');
    let r;
    try { r = spawnSync(process.execPath, ['--test', abs], { cwd: SCANNER, env, stdio: ['ignore', outFd, outFd], timeout: timeoutMs, killSignal: 'SIGKILL' }); }
    finally { fs.closeSync(outFd); }
    fs.rmSync(path.join(root, '.probe-output'), { force: true });
    // node's own on-disk module compile cache lives in the temp folder under a fixed name; it is not a test leak
    const leaked = fs.readdirSync(root).filter((n) => n !== 'node-compile-cache').sort();
    let bytes = 0;
    for (const n of leaked) bytes += sizeOf(path.join(root, n));
    return { file: path.relative(SCANNER, abs), status: r.status, timedOut: !!(r.error && r.error.code === 'ETIMEDOUT'), leaked, bytes };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const f of process.argv.slice(2)) {
    const m = measureTempLeaks(f);
    console.log(JSON.stringify({ file: m.file, status: m.status, count: m.leaked.length, bytes: m.bytes, sample: m.leaked.slice(0, 3) }));
  }
}
