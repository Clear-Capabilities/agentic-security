// PRD T4.3 — code generation as an injection sink. 5 of the 96 root-caused
// real-world misses.
//
// A NEW SINK CATEGORY, not a new sink entry. Every injection rule in this
// codebase asks "does untrusted data reach a dangerous CALL" — eval, exec,
// a query, a shell. Here there is no dangerous call at all: the program
// WRITES A FILE, and the file happens to be source code that something else
// imports and runs later. The execution is in a different process, often on a
// different machine, minutes or months afterwards.
//
// The real entries, all in code generators:
//   - a JSON-Schema `x-python-type` / `default_factory` / `customTypePath`
//     spliced verbatim into a generated .py type annotation or import
//     (GHSA-m34r-v34r-rf9q, GHSA-5578-w22f-pfx9, GHSA-386q-5hp3-95m9)
//   - field/mode strings interpolated into generated validator source
//     (GHSA-8m8r-38jm-f355)
//   - an `--extra-template-data` comment field unescaped for \r, so a
//     generated source COMMENT can hide executable statements from a reviewer
//     (GHSA-wjv6-jcfj-mf9r)
//
// Precision: a template engine writing HTML is not this. The rule requires
// BOTH that the written artifact is source code (a code-ish extension, or a
// clearly code-shaped template) AND that an interpolated value comes from a
// parsed document / config surface rather than a literal — and it stays silent
// when the value passes through an identifier validator, which is what every
// one of these advisories added as its fix.
import { blankComments } from './_comment-strip.js';

const SRC_RE = /\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i;

/** Writing a file whose name looks like source code. */
const CODE_WRITE_RE = new RegExp([
  // open("out.py", "w") / Path(...).write_text(...) / fs.writeFile("x.ts", ...)
  'open\\s{0,4}\\([^)]{0,200}\\.(?:py|js|ts|rb|go|java|php|sh)["\\\']',
  'write_text\\s{0,4}\\(', 'writeFileSync?\\s{0,4}\\([^)]{0,200}\\.(?:py|js|ts|mjs|cjs)["\\\']',
  '\\.write\\s{0,4}\\(',
].join('|'), 'i');

/** The generated artifact is program text: an import, def, class, or assignment. */
const CODE_SHAPED_RE = /(?:^|["'`\s])(?:import\s|from\s+\w|def\s|class\s|return\s|lambda\s|=\s*lambda|@\w)/;

/** Interpolation of a non-literal into that text. */
const INTERPOLATION_RE = /(?:f["'][^"']{0,200}\{|\$\{|%\s{0,2}\(|\.format\s{0,4}\(|\+\s{0,4}\w|Template\s{0,4}\(|render\w{0,10}\s{0,4}\()/;

/** Values that come from a parsed document / caller config, not from source. */
const EXTERNAL_FIELD_RE =
  /\b(?:extras?|schema|spec|definition|properties|metadata|template_?data|extra_?template|custom\w{0,20}|x-[\w-]{1,30}|config|options|field_?name|user_\w{1,20})\b/i;

/** The mitigation every one of these advisories shipped. */
const IDENTIFIER_VALIDATION_RE = new RegExp([
  'isidentifier\\s{0,4}\\(', 'str\\.isidentifier',
  'VALID\\w{0,20}_RE', '_RE\\.(?:match|fullmatch)\\s{0,4}\\(',
  're\\.(?:match|fullmatch)\\s{0,4}\\(', 'allow_?list', 'ALLOWED_\\w{1,30}',
  'sanitiz\\w{0,6}\\s{0,4}\\(', 'escape\\w{0,10}\\s{0,4}\\(',
  'validate_\\w{1,30}\\s{0,4}\\(', 'is_?safe\\w{0,20}\\s{0,4}\\(',
].join('|'), 'i');

const _lineOf = (raw, i) => raw.slice(0, i).split('\n').length;
const _win = (raw, line, half = 14) => {
  const l = raw.split('\n');
  return l.slice(Math.max(0, line - 1 - half), Math.min(l.length, line - 1 + half)).join('\n');
};

export function scanCodegenSink(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 500_000) return [];
  if (!SRC_RE.test(file)) return [];
  // Cheap relevance gate: only files that both emit and interpolate.
  if (!CODE_WRITE_RE.test(raw) || !EXTERNAL_FIELD_RE.test(raw)) return [];
  const code = blankComments(raw, /\.py$/i.test(file) ? 'py' : null);

  const out = [];
  const seen = new Set();
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    // The line must be assembling program text with an interpolation in it.
    if (!CODE_SHAPED_RE.test(text) || !INTERPOLATION_RE.test(text)) continue;
    const line = i + 1;
    const win = _win(raw, line);
    if (!CODE_WRITE_RE.test(win)) continue;            // not actually emitted as a file
    if (!EXTERNAL_FIELD_RE.test(win)) continue;        // value isn't caller-supplied
    if (IDENTIFIER_VALIDATION_RE.test(win)) continue;  // validated — the fix
    if (seen.has(line)) continue;
    seen.add(line);
    out.push({
      id: `codegen-sink:generated-source:${file}:${line}`,
      file, line,
      vuln: 'Untrusted value interpolated into generated source code',
      severity: 'high',
      cwe: 'CWE-94',
      family: 'code-injection',
      subfamily: 'generated-source',
      parser: 'CODEGEN',
      confidence: 0.5,
      description:
        'A value taken from a parsed schema/config surface is interpolated into text that this program writes out '
        + 'as source code, with no identifier or allow-list validation in between. The generated file is later '
        + 'imported and executed, so the injection executes in a different process than the one that emitted it — '
        + 'which is why no eval/exec appears anywhere near this line and why ordinary injection rules do not see it.',
      remediation:
        'Validate every interpolated value against the grammar of what it becomes — `str.isidentifier()` for a '
        + 'name, an explicit allow-list for a type or import path — and reject embedded newlines and carriage '
        + 'returns, which can smuggle statements past a generated comment.',
      checkedFor: 'an identifier/allow-list/escape validation applied to the interpolated value within 14 lines',
    });
  }
  return out;
}

export const _internals = { CODE_WRITE_RE, CODE_SHAPED_RE, INTERPOLATION_RE, EXTERNAL_FIELD_RE, IDENTIFIER_VALIDATION_RE };
