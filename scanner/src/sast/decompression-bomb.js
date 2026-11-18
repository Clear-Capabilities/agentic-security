// Decompression and image decoding with no bound on the output size (CWE-400).
//
// A compressed stream or an image header states nothing trustworthy about how
// large its decoded form is: a few kilobytes of deflate data expand to
// gigabytes, and a PNG or JPEG header can claim a canvas of 50000 x 50000
// pixels that the decoder allocates before it reads one pixel. Code that
// decodes such input and keeps the whole result (in memory or on disk) needs a
// bound on the OUTPUT, and the input size is not one.
//
// The CWE is the class, Uncontrolled Resource Consumption (CWE-400). CWE-409
// (highly compressed data) is the narrower description of the deflate case and
// sits under it; it is named in the description.
//
// Shapes, each silenced by the bound its API offers:
//   PHP   gzdecode / gzinflate / gzuncompress / zlib_decode with one argument.
//         The optional second argument is the maximum decoded length.
//   Ruby  Zlib::Inflate.inflate, Zlib.inflate, Zlib.gunzip (no limit exists),
//         and a GzipReader read to the end (`.read` with no length).
//   JS    the zlib convenience calls (sync and callback forms) without a
//         `maxOutputLength` option; a zlib / minizlib decompressor stream
//         whose 'data' handler consumes every chunk without a conditional
//         (no counter, no comparison, no check call); a DecompressionStream
//         drained whole by arrayBuffer / text / json / blob.
//   Go    an image decoded (image, jpeg, png, gif, bmp, tiff, webp) in a
//         function that never reads the header with DecodeConfig first; a
//         gzip / zlib / flate / zstd / brotli / lz4 / snappy reader read to
//         the end (io.ReadAll, ioutil.ReadAll, io.Copy) in a function with no
//         io.LimitReader, LimitedReader, CopyN or MaxBytesReader.
//   Java  a GZIPInputStream / InflaterInputStream read whole (readAllBytes,
//         toByteArray) in a file with no bounding wrapper or byte counter.
//
// Test code is skipped: a test decompresses its own fixtures.

import { callArguments } from './_call-args.js';

const TEST_PATH = /(?:^|[\\/])(?:test|tests|spec|specs|__tests__|testdata|fixtures?)[\\/]|[._-](?:test|spec)\.[a-z]+$|_test\.go$|Test\.java$/i;

const lineAt = (code, idx) => {
  let n = 1;
  for (let i = 0; i < idx && i < code.length; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
};

function finding(file, lines, line, rule, vuln, description, remediation, parser) {
  return {
    id: `decompression-bomb:${rule}:${file}:${line}`,
    file, line,
    vuln,
    severity: 'medium',
    cwe: 'CWE-400',
    family: 'resource-exhaustion',
    stride: 'Denial of Service',
    description,
    remediation,
    snippet: (lines[line - 1] || '').trim().slice(0, 200),
    parser,
    confidence: 0.5,
  };
}

const ARGS_AFTER = (code, openParenEnd) => callArguments(code.slice(openParenEnd, openParenEnd + 2000));

// ---------------------------------------------------------------- PHP
const PHP_DECODE = /(?<![\w$>:])(gzdecode|gzinflate|gzuncompress|zlib_decode)\s*\(/g;
function scanPhp(file, code, lines) {
  const out = [];
  for (const m of code.matchAll(PHP_DECODE)) {
    const args = ARGS_AFTER(code, m.index + m[0].length);
    if (!args || args.length !== 1) continue;
    const a = args[0].trim();
    if (!a || /^['"]/.test(a)) continue;
    // `function gzdecode(` is a polyfill definition, not a call.
    if (/\bfunction\s+$/.test(code.slice(Math.max(0, m.index - 20), m.index))) continue;
    const line = lineAt(code, m.index);
    out.push(finding(file, lines, line, 'php',
      'Decompression with no output limit',
      `\`${m[1]}\` is called without its maximum-length argument, so the decoded size is bounded only by memory. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust memory.`,
      `Pass the maximum decoded length as the second argument (\`${m[1]}($data, $maxLength)\`) and treat a false return as a rejected input.`,
      'PHP-DECOMPRESS'));
  }
  return out;
}

// ---------------------------------------------------------------- Ruby
const RB_INFLATE = /\bZlib(?:::Inflate)?\.(inflate|gunzip)\s*[(\s]/g;
const RB_GZ_READ_INLINE = /\bGzipReader\.(?:new|wrap|open)\b[^\n]*?\.read\b(?!\s*\(\s*[^)\s])/g;
const RB_GZ_BLOCK = /\bGzipReader\.(?:new|wrap|open|zcat)\b[^\n]*?\|\s*(\w+)\s*\|/g;
function scanRuby(file, code, lines) {
  const out = [];
  const seen = new Set();
  const push = (line, what) => {
    if (seen.has(line)) return; seen.add(line);
    out.push(finding(file, lines, line, 'ruby',
      'Decompression with no output limit',
      `${what} decompresses its whole input in one call with no limit on the decoded size. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust memory.`,
      'Inflate in chunks with `Zlib::Inflate.new` (or read a `GzipReader` with a length, `gz.read(CHUNK)`) and stop once a maximum decoded size is exceeded.',
      'RUBY-DECOMPRESS'));
  };
  for (const m of code.matchAll(RB_INFLATE)) push(lineAt(code, m.index), `\`Zlib.${m[1]}\``);
  for (const m of code.matchAll(RB_GZ_READ_INLINE)) push(lineAt(code, m.index), 'A `GzipReader` read with no length');
  for (const m of code.matchAll(RB_GZ_BLOCK)) {
    const v = m[1];
    const startLine = lineAt(code, m.index);
    const win = lines.slice(startLine - 1, startLine + 6);
    const re = new RegExp(`\\b${v}\\.read\\b(?!\\s*\\(\\s*[^)\\s])(?!\\s+\\w)`);
    const k = win.findIndex((l) => re.test(l));
    if (k >= 0) push(startLine + k, 'A `GzipReader` read with no length');
  }
  return out;
}

// ---------------------------------------------------------------- JS / TS
const JS_CONVENIENCE = /(?<![\w$])(zlib\s*\.\s*)?(gunzipSync|inflateSync|inflateRawSync|unzipSync|brotliDecompressSync|zstdDecompressSync|gunzip|inflate|inflateRaw|unzip|brotliDecompress|zstdDecompress)\s*\(/g;
const JS_STREAM_NEW = /(?:\b(?:zlib\s*\.\s*)?create(?:Gunzip|Inflate|InflateRaw|Unzip|BrotliDecompress|ZstdDecompress)|\bnew\s+(?:zlib\s*\.\s*|minizlib\s*\.\s*)?(?:Gunzip|Inflate|InflateRaw|Unzip|BrotliDecompress|ZstdDecompress))\s*\(/;
const BOUND_CALL = /\b\w*(?:check|limit|max|ratio|exceed|bound|quota|budget|guard|cap)\w*\s*\]?\s*\(/i;

function jsImportsZlib(code) {
  return /\brequire\s*\(\s*['"](?:node:)?zlib['"]\s*\)|\bfrom\s+['"](?:node:)?zlib['"]|\bfrom\s+['"]minizlib['"]|\brequire\s*\(\s*['"]minizlib['"]\s*\)/.test(code);
}

/** Text of a callback argument starting at `idx` (an arrow or function), up to its closing paren. */
function handlerText(code, openParenEnd) {
  const args = ARGS_AFTER(code, openParenEnd);
  if (!args || args.length < 2) return null;
  return args.slice(1).join(',');
}

function scanJs(file, code, lines) {
  const out = [];
  if (!jsImportsZlib(code) && !/\bDecompressionStream\b/.test(code)) return out;
  const hasZlib = jsImportsZlib(code);
  if (hasZlib) {
    for (const m of code.matchAll(JS_CONVENIENCE)) {
      const name = m[2];
      if (!m[1]) {
        // A bare name must be the zlib binding (imported by name), and not a
        // method definition or a property of some other object.
        const imported = new RegExp(`\\{[^}]*\\b${name}\\b[^}]*\\}\\s*(?:=\\s*require\\s*\\(\\s*['"](?:node:)?zlib|from\\s+['"](?:node:)?zlib)`).test(code);
        if (!imported) continue;
        if (/(?:function\s+|\.\s*|\bdef\s+)$/.test(code.slice(Math.max(0, m.index - 12), m.index))) continue;
      } else if (/\.\s*$/.test(code.slice(Math.max(0, m.index - 3), m.index))) continue;
      const args = ARGS_AFTER(code, m.index + m[0].length);
      if (!args || args.length === 0) continue;
      if (args.some((a) => /\bmaxOutputLength\b/.test(a))) continue;
      const first = args[0].trim();
      if (!first || /^['"`]/.test(first)) continue;
      const line = lineAt(code, m.index);
      out.push(finding(file, lines, line, 'js-call',
        'Decompression with no output limit',
        `\`${name}\` decompresses its whole input into one buffer and is given no \`maxOutputLength\`, so the decoded size is bounded only by memory. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust the process.`,
        'Pass `{ maxOutputLength: <bytes> }` in the options so the call fails with a range error once the decoded output passes a limit you choose.',
        'JS-DECOMPRESS'));
    }

    // Decompressor streams consumed through a 'data' handler.
    const streamVars = new Map(); // name -> line of construction
    const codeLines = lines;
    for (let i = 0; i < codeLines.length; i++) {
      if (!JS_STREAM_NEW.test(codeLines[i])) continue;
      // `x = new Unzip(...)`, `this[UNZIP] = cond ? new Unzip(...) : ...` (possibly over several lines).
      let j = i;
      let lhs = null;
      for (; j >= Math.max(0, i - 3); j--) {
        const a = codeLines[j].match(/^\s*(?:(?:const|let|var)\s+)?([\w$.]+(?:\[[\w$.'"]+\])?)\s*=(?!=)/);
        if (a) { lhs = a[1]; break; }
      }
      if (lhs) streamVars.set(lhs, i + 1);
    }
    for (const [name, ctorLine] of streamVars) {
      const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`${esc}\\s*\\.\\s*on\\s*\\(\\s*['"]data['"]\\s*,`, 'g');
      for (const m of code.matchAll(re)) {
        const body = handlerText(code, m.index + m[0].indexOf('(') + 1);
        if (body == null) continue;
        if (/\bif\s*\(|[<>]=?(?!=)|\?\s|\bthrow\b|\bdestroy\s*\(|\babort\s*\(/.test(body.replace(/=>/g, '')) || BOUND_CALL.test(body)) continue;
        // A handler that only forwards each chunk to another stream leaves the
        // bound to that stream's consumer; it is a transform, not a sink.
        if (/^\s*[\w$.\[\]]+\.(?:push|write|enqueue)\.bind\s*\(/.test(body) || /^\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*[\w$.\[\]]+\.(?:push|write|enqueue)\s*\(\s*\1\s*\)\s*;?\s*\}?\s*$/.test(body)) continue;
        const line = lineAt(code, m.index);
        out.push(finding(file, lines, line, 'js-stream',
          'Decompression with no output limit',
          `The decompressor created at line ${ctorLine} hands every decoded chunk to its 'data' handler without counting the bytes or comparing them with a limit. A small compressed input (a decompression bomb, CWE-409) can expand without bound into memory or onto disk.`,
          'Count the decoded bytes in the handler and abort (destroy the stream, raise an error) once they pass a maximum size or a maximum ratio of decoded to compressed bytes.',
          'JS-DECOMPRESS'));
      }
    }
  }
  // DecompressionStream drained whole.
  for (const m of code.matchAll(/\bpipeThrough\s*\(\s*new\s+DecompressionStream\s*\(/g)) {
    const tail = code.slice(m.index, m.index + 400);
    const stmt = tail.split(/;\s*\n|\n\s*\n/)[0];
    if (!/\.\s*(?:arrayBuffer|text|json|blob|bytes)\s*\(\s*\)/.test(stmt)) continue;
    const line = lineAt(code, m.index);
    out.push(finding(file, lines, line, 'js-web-stream',
      'Decompression with no output limit',
      'A DecompressionStream is drained into one value (arrayBuffer, text, json or blob) with no limit on the decoded size. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust memory.',
      'Read the decompressed stream with a reader, count the bytes, and cancel it once they pass a maximum size.',
      'JS-DECOMPRESS'));
  }
  return out;
}

// ---------------------------------------------------------------- Go
/** [start, end) line indexes of each top-level func. */
function goFunctions(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^func\b/.test(lines[i])) continue;
    let j = i + 1;
    if (/\{\s*\}\s*$/.test(lines[i])) { out.push([i, i + 1]); continue; }
    while (j < lines.length && !/^\}/.test(lines[j])) j++;
    out.push([i, Math.min(j + 1, lines.length)]);
    i = j;
  }
  return out;
}

const GO_IMG_DECODE = /\b(image|jpeg|png|gif|bmp|tiff|webp|imaging)\.Decode\s*\(/;
const GO_DECOMP_READER = /\b(?:gzip|zlib|flate|zstd|brotli|lz4|snappy|bzip2|lzw|xz)\.New(?:Reader|ReaderDict)\s*\(/;
const GO_BOUND = /\bio\.LimitReader\b|\bLimitedReader\b|\bio\.CopyN\b|\bMaxBytesReader\b|\bLimitReader\s*\(/;

function scanGo(file, code, lines) {
  const out = [];
  if (!/\.Decode\s*\(|\.NewReader\s*\(/.test(code)) return out;
  const imports = (pkg) => new RegExp(`"(?:image/)?${pkg}"|"[^"\\n]*/${pkg}"`).test(code);
  for (const [s, e] of goFunctions(lines)) {
    const body = lines.slice(s, e);
    // Image decode without a header (dimension) check first.
    const k = body.findIndex((l) => { const m = l.match(GO_IMG_DECODE); return m && imports(m[1] === 'imaging' ? 'imaging' : m[1]); });
    if (k >= 0) {
      const before = body.slice(0, k + 1).join('\n');
      if (!/\bDecodeConfig\s*\(/.test(before)) {
        // The check belongs before the dispatch: when the decode sits in a
        // `case` of a switch on the format, report the switch.
        let at = s + k;
        for (let b = k - 1; b >= 0 && b >= k - 12; b--) {
          if (/^\s*switch\b/.test(body[b])) { at = s + b; break; }
          if (/^\s*(?:func\b|\}\s*$)/.test(body[b]) && !/^\s*\}\s*$/.test(body[b])) break;
        }
        out.push(finding(file, lines, at + 1, 'go-image',
          'Image decoded with no dimension limit',
          'The image is decoded without reading its header first. The standard decoders allocate width x height pixels from the header before reading any pixel data, so a file of a few kilobytes that claims a huge canvas (a pixel bomb) exhausts memory.',
          'Call `image.DecodeConfig` first (on a `io.TeeReader` copy, or a re-opened reader), reject a width or height that is not positive or whose product passes a maximum pixel count, and only then decode.',
          'GO-DECOMPRESS'));
      }
    }
    // Decompressing reader read to the end.
    const text = body.join('\n');
    if (GO_DECOMP_READER.test(text) && !GO_BOUND.test(text)) {
      const vars = new Set();
      for (const l of body) {
        const a = l.match(/^\s*(\w+)\s*(?:,\s*\w+\s*)?:?=\s*\w+\.New(?:Reader|ReaderDict)\s*\(/);
        if (a && GO_DECOMP_READER.test(l)) vars.add(a[1]);
      }
      for (const v of vars) {
        const re = new RegExp(`\\b(?:io|ioutil)\\.ReadAll\\s*\\(\\s*${v}\\s*\\)|\\bio\\.Copy\\s*\\([^,]+,\\s*${v}\\s*\\)`);
        const r = body.findIndex((l) => re.test(l));
        if (r < 0) continue;
        out.push(finding(file, lines, s + r + 1, 'go-reader',
          'Decompression with no output limit',
          `The decompressing reader \`${v}\` is read to the end with no limit on the decoded size. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust memory or disk.`,
          'Wrap the reader in `io.LimitReader(r, max+1)` (or copy with `io.CopyN`) and reject the input when the limit is reached.',
          'GO-DECOMPRESS'));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- Java
function scanJava(file, code, lines) {
  const out = [];
  if (!/\b(?:GZIPInputStream|InflaterInputStream)\b/.test(code)) return out;
  if (/\bBoundedInputStream\b|\bLimitInputStream\b|\bByteStreams\.limit\b|\bmaxBytes\b|\bMAX_\w*(?:SIZE|BYTES|LENGTH)\b/.test(code)) return out;
  const vars = new Set();
  for (const m of code.matchAll(/\b(\w+)\s*=\s*new\s+(?:GZIPInputStream|InflaterInputStream)\s*\(/g)) vars.add(m[1]);
  for (const v of vars) {
    const re = new RegExp(`\\b${v}\\.readAllBytes\\s*\\(\\s*\\)|\\btoByteArray\\s*\\(\\s*${v}\\s*\\)`, 'g');
    for (const m of code.matchAll(re)) {
      const line = lineAt(code, m.index);
      out.push(finding(file, lines, line, 'java',
        'Decompression with no output limit',
        `The decompressing stream \`${v}\` is read whole with no limit on the decoded size. A small compressed input (a decompression bomb, CWE-409) can expand to gigabytes and exhaust the heap.`,
        'Read in chunks, count the decoded bytes and stop with an error once they pass a maximum size.',
        'JAVA-DECOMPRESS'));
    }
  }
  return out;
}

export function scanDecompressionBomb(file, code) {
  if (typeof code !== 'string' || !code) return [];
  const f = String(file || '');
  if (TEST_PATH.test(f)) return [];
  const lines = code.split('\n');
  if (/\.php$/i.test(f)) return scanPhp(f, code, lines);
  if (/\.rb$/i.test(f)) return scanRuby(f, code, lines);
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i.test(f) && !/\.d\.ts$/i.test(f)) return scanJs(f, code, lines);
  if (/\.go$/i.test(f)) return scanGo(f, code, lines);
  if (/\.java$/i.test(f)) return scanJava(f, code, lines);
  return [];
}
