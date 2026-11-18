import { blankComments } from './_comment-strip.js';
import { _internal as _pfh } from './path-file-handling.js';
// TOCTOU — time-of-check / time-of-use races.
//
// Two dominant shapes:
//   1. Filesystem race:  fs.access(p) → fs.open(p)
//                        os.access(p) → open(p)
//                        os.path.exists(p) → open(p)
//      The classic CWE-367. Whatever the check learned about `p` may not hold
//      by the time the use happens; an attacker who can swap symlinks wins.
//
//   2. Auth race:        if (!user.isAdmin) return; doSensitiveThing(user)
//                        if user.role != 'admin': return; do_sensitive(user)
//      Less concrete — these are gated on the check happening *first* — but
//      when the check value can be mutated by a concurrent request, we flag
//      it. Heuristic: between the guard and the use, the code awaits
//      something. The await is the race window.

const FS_CHECK_THEN_OPEN_JS = /\bfs\s*\.\s*(?:access|exists|stat|statSync|existsSync)\s*\(\s*([^,)]+?)\s*[,)][^]*?\bfs\s*\.\s*(?:open|openSync|readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(\s*\1/g;

const FS_CHECK_THEN_OPEN_PY = /\b(?:os\.access|os\.path\.exists|os\.path\.isfile|os\.stat)\s*\(\s*([^,)]+?)\s*\)[^]*?\b(?:open|os\.open|shutil\.copy|shutil\.move)\s*\(\s*\1/g;

const AUTH_CHECK_AWAIT_USE_JS = /\bif\s*\(\s*!?\s*\w+\s*(?:\.|->)\s*(?:isAdmin|isOwner|hasRole|role)\b[^)]*\)\s*[^]*?\bawait\b[^]*?\b(?:save|update|create|destroy|delete|withdraw|transfer|approve|grant)\s*\(/g;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanTOCTOU(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) {
    const code = blankComments(raw);
    let m;
    const r = new RegExp(FS_CHECK_THEN_OPEN_JS.source, FS_CHECK_THEN_OPEN_JS.flags);
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-fs:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: file existence/permission check before open',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Drop the existence/permission check and rely on `open()` to fail atomically — handle the resulting error. The check-then-open pattern is a TOCTOU race: an attacker who can swap symlinks between the check and the open wins. If you need a permission test, do it on the `open()` result\'s `fstat`, not on the path before opening.',
        parser: 'TOCTOU',
        confidence: 0.70,
      });
    }
    const ar = new RegExp(AUTH_CHECK_AWAIT_USE_JS.source, AUTH_CHECK_AWAIT_USE_JS.flags);
    while ((m = ar.exec(code))) {
      const block = m[0];
      // Heuristic: only flag if the guard variable is potentially re-read after await.
      // Approximation: guard uses `await` *between* check and side effect.
      if (!/await/.test(block)) continue;
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-auth:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: auth check then await then sensitive action',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Elevation of Privilege',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Re-fetch and re-check the authorization right before the sensitive action, ideally inside the same transaction. If the user\'s role can be revoked or downgraded mid-request, the check at the top of the handler is not load-bearing. Pattern: `BEGIN TX → SELECT FOR UPDATE → check role → side effect → COMMIT`.',
        parser: 'TOCTOU',
        confidence: 0.55,
      });
    }
  }

  if (/\.py$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    let m;
    const r = new RegExp(FS_CHECK_THEN_OPEN_PY.source, FS_CHECK_THEN_OPEN_PY.flags);
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-fs:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: file existence/permission check before open',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Use `try: open(...) except OSError` instead of the `if os.path.exists(...)` pre-check. The pre-check creates a TOCTOU window an attacker who can swap symlinks can exploit. For permission tests, use `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` then `os.fstat()`.',
        parser: 'TOCTOU',
        confidence: 0.70,
      });
    }
  }

  if (/\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i.test(fp)) {
    for (const f of verifiedThenReadByPath(fp, blankComments(raw))) push(f);
  }

  return findings;
}

// Shape 3: a same-file helper verifies a path against symlink tricks (lstat,
// realpath, isSymbolicLink) and the caller then reads the file again BY PATH.
// The verification describes the filesystem at check time; the read resolves
// the path afresh, so a symlink swapped in between is followed. The correct
// form opens once and verifies the opened handle (fstat, fd path), then reads
// through that handle. Restricted to helpers that do symlink-aware checks:
// a plain exists-then-read is shape 1 above and far noisier.
const SYMLINK_CHECK = /\b(?:lstat|lstatSync|realpath|realpathSync|isSymbolicLink)\b/;
const READ_BY_PATH = /\b(?:fs|fsPromises|fsp|promises|fs\s*\.\s*promises)\s*\.\s*(?:readFile|readFileSync|createReadStream)\s*\(\s*(\w+)\s*[,)]/g;

function verifiedThenReadByPath(fp, code) {
  const out = [];
  const fns = _pfh.functionsOf(code, 'js');
  const verifiers = fns.filter((f) => {
    const body = code.slice(f.bodyStart, f.end);
    // a helper that hands back an opened handle is the fixed form, not a check
    return SYMLINK_CHECK.test(body) && !/\breturn\s+(?:await\s+)?\w*\.?open\s*\(|\breturn\s+handle\b/.test(body);
  }).map((f) => f.name);
  if (!verifiers.length) return out;
  const callRe = new RegExp(`\\b(?:${verifiers.map((n) => n.replace(/[$]/g, '\\$')).join('|')})\\s*\\(`, 'g');
  let m;
  while ((m = callRe.exec(code))) {
    // A check called as a statement of its own (an assertion that throws),
    // not a member call on another object (`map.get(`) and not a value used
    // as data (`p = confine(...)`, which hands back the path it checked).
    const lineHead = code.slice(code.lastIndexOf('\n', m.index) + 1, m.index);
    if (!/^\s*(?:await\s+)?(?:this\s*\.\s*)?$/.test(lineHead)) continue;
    const fn = fns.filter((f) => f.bodyStart <= m.index && m.index < f.end).sort((a, b) => (b.bodyStart - a.bodyStart))[0];
    if (!fn) continue;
    // recursion is not a check-then-use
    if (code.slice(m.index).startsWith(fn.name)) continue;
    // the verified call's own arguments
    let d = 0, i = m.index + m[0].length - 1;
    for (; i < code.length; i++) { if (code[i] === '(') d++; else if (code[i] === ')') { d--; if (d === 0) break; } }
    const args = code.slice(m.index + m[0].length, i);
    // `name(args) {` is the method's own definition, not a call
    if (/^\s*(?::[^{;\n]*)?\{/.test(code.slice(i + 1, i + 200))) continue;
    const argIds = new Set((args.match(/\b[A-Za-z_$][\w$]*\b/g) || []));
    // the read that follows, within a few lines, by path
    const tailEnd = Math.min(fn.end, code.indexOf('\n', i + 1) + 1 + 400);
    const tail = code.slice(i, tailEnd).split('\n').slice(0, 7).join('\n');
    const rr = new RegExp(READ_BY_PATH.source, 'g');
    const r = rr.exec(tail);
    if (!r) continue;
    const v = r[1];
    // the read path is one the check was about: passed to it, or derived in
    // this function from something passed to it
    const before = code.slice(fn.bodyStart, m.index);
    const asg = new RegExp(`\\b${v}\\s*=\\s*([^;\\n]+)`).exec(before);
    const related = argIds.has(v) || (asg && [...argIds].some((a) => new RegExp(`\\b${a.replace(/[$]/g, '\\$')}\\b`).test(asg[1])));
    if (!related) continue;
    const line = lineOf(code, i + r.index);
    out.push({
      id: `toctou-verified-path-read:${fp}:${line}`,
      file: fp, line,
      vuln: 'TOCTOU: path verified for symlinks, then read again by path',
      severity: 'medium',
      cwe: 'CWE-367',
      family: 'toctou',
      stride: 'Tampering',
      snippet: (code.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Open the file once (with O_NOFOLLOW where available), verify the opened handle (fstat type and link count, the descriptor\'s resolved path against the root), and read through that handle. A second open by path after the check follows whatever the path names at that moment.',
      parser: 'TOCTOU',
      confidence: 0.6,
    });
  }
  return out;
}
