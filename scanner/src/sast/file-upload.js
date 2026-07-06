// CWE-434 — Unrestricted file upload (#6). A whole CWE that had NO detector.
//
// Bread-and-butter for the vibecoder stacks (Next.js / Express / Supabase /
// Firebase / FastAPI / Flask): an upload endpoint that writes an attacker-
// supplied file without restricting its type/extension/size, or that uses the
// client-supplied filename as the on-disk destination (also CWE-22 path
// traversal — `../../x` in the filename escapes the upload dir).
//
// Precision is the whole game here (uploads are everywhere). Each rule fires
// only on a clear unrestricted shape and is suppressed by the standard guard:
//   - Multer configured with NEITHER fileFilter NOR limits → unrestricted.
//   - A write whose destination is built from the CLIENT filename
//     (file.originalname / req.files.*.name / UploadFile.filename) with no
//     sanitizer (basename / uuid / randomUUID / sanitize / whitelist) nearby.
// A validated upload (fileFilter+limits, or a generated/sanitized name) does
// NOT match.
import { blankComments } from './_comment-strip.js';

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;

const _lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;
const _snip = (raw, line) => (raw.split('\n')[line - 1] || '').trim().slice(0, 200);
// A sanitizer for the destination filename anywhere in the ±6-line window.
const NAME_SANITIZER = /\b(?:basename|randomUUID|uuidv4|uuid4|uuid\.v4|nanoid|sanitize[-_]?filename|sanitizeFilename|slugify|crypto\.random|secure_filename|werkzeug)\b/i;

function _window(raw, line, half = 6) {
  const lines = raw.split('\n');
  const start = Math.max(0, line - 1 - half);
  const end = Math.min(lines.length, line - 1 + half);
  return lines.slice(start, end).join('\n');
}

function mk(file, raw, line, sub, severity, vuln, description, remediation) {
  return {
    id: `file-upload:${sub}:${file}:${line}`,
    severity, file, line,
    vuln, cwe: 'CWE-434',
    family: 'unrestricted-file-upload',
    parser: 'FILE-UPLOAD',
    subfamily: sub,
    snippet: _snip(raw, line),
    description,
    remediation,
  };
}

function scanJs(file, raw, code, out, seen) {
  const push = (line, mkr) => { const k = `${line}`; if (seen.has(k)) return; seen.add(k); out.push(mkr); };

  // 1) Multer with neither fileFilter nor limits → unrestricted upload config.
  //    Matches `multer()` and `multer({ ... })` whose options lack both guards.
  const multerRe = /\bmulter\s*\(\s*(?:\)|\{([\s\S]*?)\}\s*\))/g;
  let m;
  while ((m = multerRe.exec(code))) {
    const opts = m[1] || '';
    if (/\bfileFilter\b/.test(opts) || /\blimits\b/.test(opts)) continue; // guarded
    const line = _lineOf(raw, m.index);
    push(line, mk(file, raw, line, 'multer-unrestricted', 'medium',
      'Unrestricted file upload — Multer configured with no fileFilter and no limits',
      'This Multer instance accepts any file of any size. An attacker can upload an executable, oversized, or malicious file (web shell, zip bomb).',
      'Add a `fileFilter` that allow-lists MIME types / extensions and a `limits: { fileSize }` cap. Store uploads outside the web root and never serve them with their uploaded name.'));
  }

  // 2) Write whose destination is built from the CLIENT-supplied filename.
  //    e.g. path.join(dir, file.originalname) / req.files.x.mv('...'+req.files.x.name)
  //    Also CWE-22: `../../` in the filename escapes the upload dir.
  const clientName = /\b(?:\w+\.originalname|req\.files(?:\.\w+|\[[^\]]+\])?\.name)\b/;
  const writeSinks = [
    /\.mv\s*\(/,                         // express-fileupload
    /\b(?:fs\.)?(?:writeFile|writeFileSync|createWriteStream)\s*\(/,
    /\bpath\.join\s*\(/,                 // building the dest path
  ];
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!clientName.test(lines[i])) continue;
    if (!writeSinks.some(re => re.test(lines[i]))) continue;
    const line = i + 1;
    if (NAME_SANITIZER.test(_window(raw, line))) continue; // sanitized/generated name → safe
    push(line, mk(file, raw, line, 'client-filename-dest', 'high',
      'Unrestricted file upload — client-supplied filename used as the write destination',
      'The uploaded file is written using its client-controlled name. An attacker can choose the extension (upload `shell.php`) or embed path traversal (`../../etc/x`) to escape the upload directory.',
      'Never trust the uploaded filename. Generate a server-side name (uuid/nanoid) and validate the extension against an allow-list; write with path.basename() into a fixed directory outside the web root.'));
  }
}

function scanPy(file, raw, code, out, seen) {
  const push = (line, mkr) => { const k = `${line}`; if (seen.has(k)) return; seen.add(k); out.push(mkr); };
  // Flask: request.files['x'].save(os.path.join(dir, file.filename))
  // FastAPI: open(file.filename, ...) / shutil.copyfileobj(upload.file, open(upload.filename))
  const clientName = /\b\w+\.filename\b/;
  const writeSinks = [/\.save\s*\(/, /\bopen\s*\(/, /\bos\.path\.join\s*\(/, /\bcopyfileobj\s*\(/];
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!clientName.test(lines[i])) continue;
    if (!writeSinks.some(re => re.test(lines[i]))) continue;
    const line = i + 1;
    if (NAME_SANITIZER.test(_window(raw, line))) continue; // secure_filename / uuid → safe
    push(line, mk(file, raw, line, 'client-filename-dest', 'high',
      'Unrestricted file upload — client-supplied filename used as the write destination',
      'The uploaded file is saved under its client-controlled name. An attacker can choose the extension or embed path traversal to escape the upload directory.',
      'Use werkzeug secure_filename() (Flask) or generate a uuid name; validate the extension against an allow-list and write into a fixed directory outside the web root.'));
  }
}

export function scanFileUpload(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const isJs = JS_EXT.test(fp), isPy = PY_EXT.test(fp);
  if (!isJs && !isPy) return [];
  // Cheap relevance gate — skip files with no upload surface.
  if (!/\b(?:multer|originalname|req\.files|UploadFile|\.filename|createWriteStream|\.mv\s*\()/i.test(raw)) return [];
  const code = blankComments(raw, isPy ? 'py' : null);
  const out = [];
  const seen = new Set();
  try { if (isJs) scanJs(fp, raw, code, out, seen); } catch { /* per-file best-effort */ }
  try { if (isPy) scanPy(fp, raw, code, out, seen); } catch { /* per-file best-effort */ }
  return out;
}
