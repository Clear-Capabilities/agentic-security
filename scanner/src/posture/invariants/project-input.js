// Reading contracts, ledgers and disposable fixtures from a project directory (X-407.AC03).
//
// The CLI and the MCP tool both start from files, and both must read them the same bounded, link-free way. This is the only
// place that does: a fixture is a small directory of text files (no symlinks, no hidden or dependency directories, a file and
// byte ceiling), a contract or ledger is one bounded JSON file. Path CONFINEMENT is the caller's (the MCP tool passes its
// session-root confinement; the CLI resolves under the working directory), so this module takes already-resolved absolute paths
// and refuses anything that is a link or not a regular file.
import * as fs from 'node:fs';
import * as path from 'node:path';

const INPUT_LIMITS = Object.freeze({ files: 64, fileBytes: 256 * 1024, totalBytes: 1024 * 1024, jsonBytes: 1024 * 1024 });
// hidden directories (.git and the like) are skipped by the leading-dot rule in the walk below
const SKIP_DIRS = new Set(['node_modules']);

/** Read one bounded JSON document. `{ ok, value }` or `{ ok: false, reason }`; never throws. */
export function readJsonFile(abs) {
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink() || !st.isFile()) return { ok: false, reason: 'not a regular file' };
    if (st.size > INPUT_LIMITS.jsonBytes) return { ok: false, reason: `larger than ${INPUT_LIMITS.jsonBytes} bytes` };
    return { ok: true, value: JSON.parse(fs.readFileSync(abs, 'utf8')) };
  } catch (e) {
    return { ok: false, reason: `unreadable: ${String(e?.message || e).slice(0, 120)}` };
  }
}

/** Read a fixture directory into `{ relative/posix/path: text }`. Refuses links, non-text files and anything over the limits. */
export function readFixtureDir(abs) {
  const files = {};
  let total = 0;
  const errors = [];
  const walk = (dir, rel) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); } catch (e) { errors.push(`unreadable directory ${rel || '.'}`); return; }
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { errors.push(`${r}: symbolic links are refused`); continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name), r); continue; }
      if (!e.isFile() || e.name.startsWith('.')) continue;
      if (Object.keys(files).length >= INPUT_LIMITS.files) { errors.push(`more than ${INPUT_LIMITS.files} files`); return; }
      const p = path.join(dir, e.name);
      const size = fs.statSync(p).size;
      if (size > INPUT_LIMITS.fileBytes || total + size > INPUT_LIMITS.totalBytes) { errors.push(`${r}: over the size limit`); continue; }
      const text = fs.readFileSync(p, 'utf8');
      if (text.includes('\u0000')) { errors.push(`${r}: not a text file`); continue; }
      files[r] = text; total += size;
    }
  };
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink() || !st.isDirectory()) return { ok: false, files: {}, errors: ['the fixture path is not a directory'] };
  } catch { return { ok: false, files: {}, errors: ['the fixture directory does not exist'] }; }
  walk(abs, '');
  return { ok: errors.length === 0 && Object.keys(files).length > 0, files, errors: Object.keys(files).length ? errors : [...errors, 'the fixture directory holds no files'] };
}
