// Temp directories for tests that clean up after themselves.
//
//   const dir = mkTestTmp('my-test-');   // same as fs.mkdtempSync(path.join(os.tmpdir(), 'my-test-'))
//
// Every directory made this way is removed (recursive, forced) when the test
// process exits, whether the tests passed, failed or threw. Before this helper
// most test files created directories under the OS temp folder and never
// removed them, so a full run left thousands behind (and made later runs
// slower). `node --test` runs each file in its own process, so "process exit"
// is "end of this file".
//
// Removal is best effort and never throws: a directory a test left read-only
// is made writable first, and a failure to remove is ignored rather than
// turned into a test failure at exit.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const made = new Set();
let hooked = false;

function chmodTree(p) {
  let st;
  try { st = fs.lstatSync(p); } catch { return; }
  if (st.isSymbolicLink()) return;
  try { fs.chmodSync(p, st.isDirectory() ? 0o700 : 0o600); } catch { /* ignore */ }
  if (!st.isDirectory()) return;
  let names = [];
  try { names = fs.readdirSync(p); } catch { return; }
  for (const n of names) chmodTree(path.join(p, n));
}

export function removeTmp(dir) {
  made.delete(dir);
  try { fs.rmSync(dir, { recursive: true, force: true }); return; } catch { /* retry below */ }
  try { chmodTree(dir); fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

function cleanupAll() { for (const d of [...made]) removeTmp(d); }

/** Creates a unique directory under the OS temp folder and schedules its removal at process exit. */
export function mkTestTmp(prefix = 'test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  made.add(dir);
  if (!hooked) { hooked = true; process.on('exit', cleanupAll); }
  return dir;
}
