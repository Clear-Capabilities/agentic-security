// Workspace neutralization and the leakage gate (PRD 6, benchmark integrity).
//
// A model must be scored on whether it can find the defect, not on whether it can read the answer. Before any arm sees a
// workspace this module (1) copies it, (2) strips comments while keeping every line number (so a span still points at the same
// code), (3) renames files whose NAME carries the weakness class, and (4) runs the existing custody audit
// (`custody.auditWorkspace`: answer-key file names, symlinks, protected terms, advisory ids) plus three checks of its own:
// a weakness id anywhere in the content, a vulnerability-describing comment that was left in, and a weakness-bearing file name
// that the policy did not rename. Any hit quarantines the workspace: the entry is recorded as quarantined and is NOT scanned.
//
// What this is not: a proof that no paraphrase gets through. Comment stripping is best effort (a regular expression literal
// containing `//` can be mis-read), and an identifier that happens to describe the bug stays. The audit result is recorded on
// every run so a reader can see exactly what was checked.
import fs from 'node:fs';
import path from 'node:path';
import { auditWorkspace } from '../custody.js';
import { STATE_DIR_NAME } from '../../state-dir.js';

const C_LIKE = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.go', '.rs', '.kt', '.kts', '.swift', '.scala', '.php']);
const HASH_LIKE = new Set(['.py', '.rb', '.sh', '.bash', '.pl', '.yaml', '.yml', '.tf', '.toml']);
const HASH_AND_C = new Set(['.php']);
// languages where a single quote opens a string of any length; elsewhere it is a short character literal (or a Rust lifetime)
const SQ_STRING = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.php']);
const SKIP = new Set(['.git', 'node_modules', STATE_DIR_NAME]);
const CWE_NAME = /cwe[-_]?\d{1,5}/i;
const CWE_CONTENT = /\bcwe[-_ ]?\d{2,5}\b/i;
const DESCRIPTIVE_COMMENT = /\b(vulnerab\w*|insecure|exploit\w*|potential flaw|flaw:|fixed by|should be (?:sanitized|escaped|validated)|\bBAD\b|\bGOOD\b|sink|taint\w*)\b/i;

/** Remove comments, keeping newlines. String-aware for ' " and ` quotes; best effort, see the file header. */
export function stripComments(text, ext) {
  const cLike = C_LIKE.has(ext);
  const hash = HASH_LIKE.has(ext) || HASH_AND_C.has(ext);
  if (!cLike && !hash) return text;
  const s = String(text);
  let out = '';
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    const two = s.substr(i, 2);
    if (cLike && two === '//') { while (i < n && s[i] !== '\n') i++; continue; }
    if (cLike && two === '/*') { i += 2; while (i < n && s.substr(i, 2) !== '*/') { if (s[i] === '\n') out += '\n'; i++; } i += 2; continue; }
    if (hash && c === '#' && !(ext === '.php' && s[i + 1] === '[')) { while (i < n && s[i] !== '\n') i++; continue; }
    if (c === '"' || c === '`' || (c === "'" && (hash || SQ_STRING.has(ext) || /^'(?:\\.|[^'\\\n]){1,12}'/.test(s.slice(i, i + 16))))) {
      const triple = (hash && ext === '.py' && s.substr(i, 3) === c.repeat(3)) ? c.repeat(3) : null;
      const q = triple || c;
      out += q; i += q.length;
      while (i < n) {
        if (s[i] === '\\') { out += s.substr(i, 2); i += 2; continue; }
        if (s.substr(i, q.length) === q) { out += q; i += q.length; break; }
        if (!triple && q !== '`' && s[i] === '\n') break; // an unterminated string ends at the line
        out += s[i]; i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

/** `*` matches within a path segment, `**` across segments; everything else is literal. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; } else if (c === '*') re += '[^/]*'; else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`, 'i');
}

const isText = (buf) => !buf.subarray(0, 4096).includes(0);

function copyTree(src, dest, files = []) {
  fs.mkdirSync(dest, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (SKIP.has(e.name)) continue;
    const s = path.join(src, e.name); const d = path.join(dest, e.name);
    if (e.isSymbolicLink()) { files.push({ rel: path.relative(dest, d), symlink: true }); fs.symlinkSync(fs.readlinkSync(s), d); continue; }
    if (e.isDirectory()) { copyTree(s, d, files); continue; }
    if (e.isFile()) fs.copyFileSync(s, d);
  }
  return files;
}

function listFiles(root, rel = '', out = []) {
  for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) listFiles(root, r, out); else if (e.isFile()) out.push(r);
  }
  return out;
}

/**
 * @returns {{ok: boolean, quarantined: boolean, destDir: string|null, fileMap: Record<string,string>, leaks: object[], audit: object}}
 * `fileMap` maps original relative paths to staged ones, so a label's span can be located without telling the arm.
 */
export function stageNeutralized({ srcDir, destDir, policy = {}, terms = [] }) {
  fs.rmSync(destDir, { recursive: true, force: true });
  copyTree(srcDir, destDir);
  const leaks = [];
  const fileMap = {};
  const renamedStems = [];
  let n = 0;
  // 0. remove files the policy names (change logs, advisories and the like) before anything is judged
  if (Array.isArray(policy.removePaths) && policy.removePaths.length) {
    const res = policy.removePaths.map(globToRegExp);
    for (const rel of listFiles(destDir)) if (res.some((re) => re.test(rel))) fs.rmSync(path.join(destDir, rel), { force: true });
  }
  // 1. rename weakness-bearing file names (and note the stem so class/module references can follow)
  for (const rel of listFiles(destDir)) {
    const base = path.basename(rel);
    if (!CWE_NAME.test(rel)) { fileMap[rel] = rel; continue; }
    if (!policy.renameFiles) { fileMap[rel] = rel; leaks.push({ kind: 'weakness-in-file-name', file: rel, detail: 'the file name states the weakness class and the policy does not rename files' }); continue; }
    const ext = path.extname(base);
    const stem = base.slice(0, base.length - ext.length);
    const next = `case${String(++n).padStart(4, '0')}${ext}`;
    const relNext = path.posix.join(path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel).replace(CWE_NAME, 'dir'), next);
    fs.mkdirSync(path.dirname(path.join(destDir, relNext)), { recursive: true });
    fs.renameSync(path.join(destDir, rel), path.join(destDir, relNext));
    fileMap[rel] = relNext;
    renamedStems.push([stem, next.slice(0, next.length - ext.length)]);
  }
  for (const d of fs.readdirSync(destDir, { withFileTypes: true })) if (d.isDirectory()) { try { fs.rmdirSync(path.join(destDir, d.name)); } catch { /* not empty */ } }
  // 2. strip comments, follow renamed stems in text
  for (const rel of listFiles(destDir)) {
    const p = path.join(destDir, rel);
    let buf; try { buf = fs.readFileSync(p); } catch { continue; }
    if (!isText(buf)) continue;
    let text = buf.toString('utf8');
    const original = text;
    if (policy.stripComments) text = stripComments(text, path.extname(rel).toLowerCase());
    else {
      const cm = text.split('\n').findIndex((l) => /(?:\/\/|\/\*|\*|#)/.test(l) && DESCRIPTIVE_COMMENT.test(l));
      if (cm !== -1) leaks.push({ kind: 'descriptive-comment', file: rel, line: cm + 1, detail: 'a comment describes the weakness; set leakagePolicy.stripComments' });
    }
    for (const [from, to] of renamedStems) text = text.split(from).join(to);
    if (CWE_CONTENT.test(text)) leaks.push({ kind: 'weakness-id-in-content', file: rel, detail: 'the content names a CWE id' });
    if (text !== original) fs.writeFileSync(p, text);
  }
  // 3. the existing custody audit (answer-key names, symlinks, protected terms, advisory ids)
  const audit = auditWorkspace(destDir, terms);
  for (const l of audit.leaks) leaks.push(l);
  if (leaks.length) { fs.rmSync(destDir, { recursive: true, force: true }); return { ok: false, quarantined: true, destDir: null, fileMap, leaks, audit: { scannedFiles: audit.scannedFiles, leaks: leaks.length } }; }
  return { ok: true, quarantined: false, destDir, fileMap, leaks: [], audit: { scannedFiles: audit.scannedFiles, leaks: 0 } };
}
