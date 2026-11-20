// Request parsing with its size limit turned off or never applied (CWE-770,
// CWE-400, CWE-674), and archives from an upload extracted with no bound on
// the extracted size (CWE-400, CWE-409 named in the text).
//
// Three shapes, each written from the documented behaviour of the API:
//
//   limit-disabled  A framework or parser limit explicitly switched off.
//     Django       DATA_UPLOAD_MAX_MEMORY_SIZE / DATA_UPLOAD_MAX_NUMBER_FIELDS /
//                  DATA_UPLOAD_MAX_NUMBER_FILES = None ("None disables the check").
//     Spring Boot  multipart max-file-size / max-request-size, Tomcat
//                  max-swallow-size / max-http-form-post-size, codec and WebFlux
//                  max-in-memory-size set to -1 (unlimited).
//     Commons FileUpload  setSizeMax / setFileSizeMax / setFileCountMax(-1), and
//                  an upload parser built and used in a file that never sets a
//                  size maximum (the library default is -1, no limit).
//     Express / body-parser  a `limit` of Infinity or of gigabytes; multer,
//                  busboy and formidable size limits set to Infinity.
//     libxml2      the HUGE option, which lifts the parser's hard limits on
//                  depth and text size: lxml `huge_tree=True`, Nokogiri
//                  `ParseOptions::HUGE` / `.huge`, PHP `LIBXML_PARSEHUGE`. Only
//                  in a file that also reads request input.
//     JSON nesting Ruby `JSON.parse(..., max_nesting: false|nil|0)`, Jackson
//                  StreamReadConstraints raised to Integer.MAX_VALUE (CWE-674
//                  for nesting).
//   body-unbounded  Go reads a whole request body into memory (io.ReadAll of
//     r.Body, gin GetRawData) where the file never applies MaxBytesReader or
//     a LimitReader (net/http sets no body limit); Node collects a request's
//     'data' events into one buffer with no size check, or calls raw-body
//     without a `limit`.
//   archive-bomb  An archive or compressed payload that came from the request is
//     extracted or decompressed with no check of the extracted size: Python
//     zlib/gzip/bz2/lzma.decompress of request data and zipfile from an upload;
//     Java ZipInputStream over an upload stream; Go archive/zip in a handler;
//     PHP ZipArchive over $_FILES; JS adm-zip over an uploaded file. Silent when
//     the function reads entry sizes (file_size, getSize, UncompressedSize64,
//     header.size, statIndex), wraps the stream in a bounded reader, or compares
//     a running total with a maximum.
//
// Test code is skipped. Every rule names the bound that silences it.

import { langOf } from './convention-deviation-values.js';

const TEST_PATH_RE = /(?:^|[\\/])(?:tests?|specs?|__tests__|__mocks__|testdata|fixtures?|e2e|bench(?:mark)?s?|examples?)[\\/]|[._-](?:test|spec)\.[a-z]{1,4}$|Tests?\.(?:java|kt|cs)$|_test\.go$|(?:^|[\\/])test_\w{1,80}\.py$|_spec\.rb$/i;
const SPRING_PROPS_RE = /(?:^|[\\/])application(?:[-.][\w-]+)?\.(?:properties|ya?ml)$/i;

const lineAt = (code, idx) => {
  let n = 1;
  for (let i = 0; i < idx && i < code.length; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
};

function finding(file, code, idx, rule, cwe, vuln, description, remediation) {
  const line = lineAt(code, idx);
  return {
    id: `resource-limit:${rule}:${file}:${line}`,
    file, line, vuln, severity: 'medium', cwe,
    family: 'resource-exhaustion', parser: 'RESOURCE',
    stride: 'Denial of Service', confidence: 0.6,
    description, remediation,
    snippet: (code.split('\n')[line - 1] || '').trim().slice(0, 200),
  };
}

/** Request evidence per language: any framework request accessor in the file. */
const REQUEST_EVIDENCE = {
  py: /\brequest\s*\.\s*(?:args|form|values|GET|POST|FILES|files|data|body|json|get_json|get_data|stream)\b|\bUploadFile\b/,
  rb: /\bparams\s*\[|\brequest\s*\.\s*(?:body|params|raw_post)\b/,
  php: /\$_(?:GET|POST|REQUEST|FILES)\b|\$request\s*->|php:\/\/input/,
  js: /\b(?:req|request|ctx)\s*\.\s*(?:body|query|params|files?|rawBody)\b/,
  java: /\bHttpServletRequest\b|@(?:RequestBody|RequestParam|PathVariable)\b|\bMultipartFile\b/,
  kt: /\bHttpServletRequest\b|@(?:RequestBody|RequestParam)\b|\bcall\s*\.\s*receive/,
  go: /\*http\.Request\b|\bgin\.Context\b|\becho\.Context\b/,
  cs: /\bRequest\s*\.\s*(?:Body|Form|Query)\b|\[From(?:Body|Form|Query)\]/,
};

// ---------------------------------------------------------------------------
// limit-disabled
// ---------------------------------------------------------------------------

function scanLimitDisabled(file, code, lang) {
  const out = [];
  const push = (idx, what, cwe, remediation, why) => out.push(finding(file, code, idx, 'limit-disabled', cwe,
    `Request size limit disabled: ${what}`,
    `${why} With the limit off, one request can make the server read, parse and hold as much data as the client sends, so a single large or deeply nested body exhausts memory or CPU for every user.`,
    remediation));

  if (SPRING_PROPS_RE.test(file)) {
    const re = /^[ \t]*((?:spring\.servlet\.multipart\.|server\.tomcat\.|spring\.codec\.|spring\.webflux\.multipart\.)?(max-file-size|max-request-size|max-swallow-size|max-http-form-post-size|max-in-memory-size|max-disk-usage-per-part))[ \t]*[=:][ \t]*["']?-1\b/gm;
    for (const m of code.matchAll(re)) {
      push(m.index + (m[0].length - m[0].trimStart().length), `${m[1]} = -1 (unlimited)`, 'CWE-770',
        `Set ${m[2]} to the largest size the application really accepts (for example 10MB) instead of -1.`,
        `In Spring Boot and Tomcat, -1 for ${m[2]} means no limit.`);
    }
    return out;
  }

  if (lang === 'py') {
    for (const m of code.matchAll(/^[ \t]*(DATA_UPLOAD_MAX_MEMORY_SIZE|DATA_UPLOAD_MAX_NUMBER_FIELDS|DATA_UPLOAD_MAX_NUMBER_FILES)\s*=\s*None\b/gm)) {
      push(m.index, `${m[1]} = None`, 'CWE-770',
        `Leave ${m[1]} at its default or set an explicit number; route a view that needs large bodies through request.stream with its own cap.`,
        `Django documents that setting ${m[1]} to None disables the check.`);
    }
    if (REQUEST_EVIDENCE.py.test(code)) {
      for (const m of code.matchAll(/\b(?:XMLParser|HTMLParser|XMLPullParser|iterparse)\s*\([^)]{0,300}\bhuge_tree\s*=\s*True\b/g)) {
        push(m.index, 'lxml parser with huge_tree=True', 'CWE-400',
          'Drop huge_tree=True for any document a client can send; libxml2\'s default limits on depth and text size are the protection.',
          'huge_tree=True lifts libxml2\'s limits on tree depth and text node size, and this file parses request input.');
      }
    }
  }

  if (lang === 'rb') {
    if (REQUEST_EVIDENCE.rb.test(code) && /\bNokogiri\b/.test(code)) {
      for (const m of code.matchAll(/\bParseOptions\s*::\s*HUGE\b|(?<![\w.])(?:config|cfg|c|opts|options)\s*\.\s*huge\b/g)) {
        push(m.index, 'Nokogiri parse option HUGE', 'CWE-400',
          'Remove the HUGE option for documents from requests; libxml2\'s default limits are the protection.',
          'HUGE lifts libxml2\'s hard limits on depth and text size, and this file parses request input.');
      }
    }
    for (const m of code.matchAll(/\bJSON\s*\.\s*parse!?\s*\([^)]{0,300}\bmax_nesting\s*:\s*(?:false|nil|0)\b/g)) {
      push(m.index, 'JSON.parse with max_nesting disabled', 'CWE-674',
        'Keep the default max_nesting (100) or set a small explicit depth.',
        'max_nesting false, nil or 0 removes the depth limit, so a deeply nested document drives the parser\'s recursion as deep as the client likes.');
    }
  }

  if (lang === 'php') {
    if (REQUEST_EVIDENCE.php.test(code)) {
      for (const m of code.matchAll(/\bLIBXML_PARSEHUGE\b/g)) {
        push(m.index, 'LIBXML_PARSEHUGE', 'CWE-400',
          'Drop LIBXML_PARSEHUGE for documents from requests; libxml2\'s default limits are the protection.',
          'LIBXML_PARSEHUGE lifts libxml2\'s hard limits on depth and text size, and this file parses request input.');
      }
    }
  }

  if (lang === 'java' || lang === 'kt') {
    for (const m of code.matchAll(/\.\s*set(SizeMax|FileSizeMax|FileCountMax)\s*\(\s*-1L?\s*\)/g)) {
      push(m.index, `set${m[1]}(-1)`, 'CWE-770',
        `Pass the largest value the application accepts to set${m[1]} instead of -1.`,
        `In Commons FileUpload, -1 for ${m[1]} means no limit.`);
    }
    if (/\b(?:parseRequest|parseParameterMap|getItemIterator)\s*\(/.test(code) && !/\bset(?:SizeMax|FileSizeMax)\s*\(/.test(code)) {
      for (const m of code.matchAll(/\bnew\s+(?:ServletFileUpload|JakartaServletFileUpload|JakartaServletDiskFileUpload|DiskFileUpload|FileUpload)\s*\(/g)) {
        push(m.index, 'Commons FileUpload parser with no size maximum', 'CWE-770',
          'Call setSizeMax (whole request) and setFileSizeMax (each file), and setFileCountMax, before parseRequest.',
          'Commons FileUpload defaults sizeMax and fileSizeMax to -1 (no limit), and this file parses a request without setting either.');
      }
    }
    for (const m of code.matchAll(/\.\s*(maxNestingDepth|maxStringLength|maxNumberLength)\s*\(\s*(?:Integer\s*\.\s*MAX_VALUE|Int\s*\.\s*MAX_VALUE)\s*\)/g)) {
      push(m.index, `Jackson StreamReadConstraints.${m[1]}(Integer.MAX_VALUE)`, m[1] === 'maxNestingDepth' ? 'CWE-674' : 'CWE-400',
        `Keep Jackson's default ${m[1]} or raise it to a specific, documented value.`,
        `Jackson's StreamReadConstraints exist to bound parsing of untrusted JSON; ${m[1]}(Integer.MAX_VALUE) removes that bound.`);
    }
  }

  if (lang === 'js') {
    const bp = /\b(?:express|bodyParser|body_parser)\s*\.\s*(?:json|urlencoded|raw|text)\s*\(\s*\{[^{}]{0,400}?\blimit\s*:\s*(?:Infinity|Number\s*\.\s*(?:MAX_SAFE_INTEGER|POSITIVE_INFINITY|MAX_VALUE)|['"`]\s*\d+(?:\.\d+)?\s*(?:gb|tb)\s*['"`])/gi;
    for (const m of code.matchAll(bp)) {
      push(m.index, 'body parser with an unbounded or gigabyte limit', 'CWE-770',
        "Set the parser limit to the largest body a route really needs (the default is '100kb'); stream genuinely large uploads to storage with their own cap.",
        'The body parser buffers and parses the whole body before the handler runs, and this limit lets a client send as much as it likes.');
    }
    for (const m of code.matchAll(/\b(fileSize|maxFileSize|maxFieldsSize|maxTotalFileSize|fieldSize)\s*:\s*(?:Infinity|Number\s*\.\s*(?:MAX_SAFE_INTEGER|POSITIVE_INFINITY|MAX_VALUE))\b/g)) {
      if (!/\b(?:multer|busboy|Busboy|formidable|Formidable|IncomingForm)\b/.test(code)) break;
      push(m.index, `upload limit ${m[1]}: Infinity`, 'CWE-770',
        `Set ${m[1]} to the largest upload the application accepts.`,
        `${m[1]} bounds how much of an upload the parser will accept, and Infinity removes the bound.`);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// body-unbounded
// ---------------------------------------------------------------------------

/** Every server this file starts listens on loopback only: no remote caller can send it a body. */
function loopbackOnly(code, lang) {
  const re = lang === 'go'
    ? /\bListenAndServe(?:TLS)?\s*\(\s*("[^"]*"|[A-Za-z_][\w.]*)/g
    : /\.\s*listen\s*\(([^)]{0,200})\)/g;
  let n = 0;
  for (const m of code.matchAll(re)) {
    n++;
    if (!/['"`](?:127\.0\.0\.1|localhost|::1|\[::1\])(?::\d*)?['"`]/.test(m[1])) return false;
  }
  return n > 0;
}

function scanBodyUnbounded(file, code, lang) {
  const out = [];
  if ((lang === 'js' || lang === 'go') && loopbackOnly(code, lang)) return out;
  if (lang === 'go') {
    if (/\bMaxBytesReader\b|\bLimitReader\b|\bLimitedReader\b|\bBodyLimit\b|\bContentLength\s*[<>]/.test(code)) return out;
    const reqNames = new Set([...code.matchAll(/\b([A-Za-z_]\w*)\s+\*http\.Request\b/g)].map((m) => m[1]));
    const ctxNames = new Set([...code.matchAll(/\b([A-Za-z_]\w*)\s+(?:\*gin\.Context|echo\.Context)\b/g)].map((m) => m[1]));
    for (const m of code.matchAll(/\b(?:io|ioutil)\s*\.\s*ReadAll\s*\(\s*([A-Za-z_]\w*)(\s*\.\s*Request(?:\s*\(\s*\))?)?\s*\.\s*Body\s*\)/g)) {
      const ok = m[2] ? ctxNames.has(m[1]) : reqNames.has(m[1]);
      if (!ok) continue;
      out.push(goBody(file, code, m.index, `io.ReadAll(${m[1]}${m[2] ? m[2].replace(/\s+/g, '') : ''}.Body)`));
    }
    for (const m of code.matchAll(/\b([A-Za-z_]\w*)\s*\.\s*GetRawData\s*\(\s*\)/g)) {
      if (ctxNames.has(m[1])) out.push(goBody(file, code, m.index, `${m[1]}.GetRawData()`));
    }
    return out;
  }
  if (lang === 'js') {
    // req.on('data', chunk => { body += chunk }) / chunks.push(chunk), with no size check in the handler.
    for (const m of code.matchAll(/\b(req|request)\s*\.\s*on\s*\(\s*['"]data['"]\s*,\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*(?:=>)?\s*\{?/g)) {
      const start = m.index + m[0].length;
      // The handler's text up to the matching paren of on(.
      let depth = 1, k = code.indexOf('(', m.index) + 1;
      for (; k < code.length && depth > 0; k++) { if (code[k] === '(') depth++; else if (code[k] === ')') depth--; }
      const handler = code.slice(start, k);
      const chunk = m[2];
      const compact = handler.replace(/[ \t]/g, '');
      const followedByName = (needle) => {
        let at = compact.indexOf(needle);
        while (at !== -1) {
          if (!/[\w$]/.test(compact[at + needle.length] || '')) return true;
          at = compact.indexOf(needle, at + 1);
        }
        return false;
      };
      const grows = followedByName('+=' + chunk) || followedByName('.push(' + chunk)
        || (compact.includes('Buffer.concat(') && followedByName(chunk));
      if (!grows) continue;
      // Any comparison, destroy, 413 or limit in the handler or nearby means the size is checked.
      const fnWindow = code.slice(Math.max(0, m.index - 800), Math.min(code.length, k + 400));
      if (/\b(?:length|byteLength|size|total|received|bytes)\s*>|>\s*(?:MAX|LIMIT|max|limit)\w*|\.destroy\s*\(|\b413\b|\blimit\b|\bmaxBytes|\bMAX_\w+/.test(handler) || /\b413\b|\.destroy\s*\(|\bmaxBytes|\bMAX_BODY|\bbodyLimit\b/.test(fnWindow)) continue;
      out.push(finding(file, code, m.index, 'body-unbounded', 'CWE-770',
        'Request body collected with no size limit',
        `Every 'data' chunk of the request is appended to one buffer and nothing compares the running size with a maximum. Node's HTTP server sets no body limit, so one client can stream data until the process runs out of memory.`,
        'Count the bytes received and respond 413 and destroy the request once the count passes a maximum, or use a body parser with an explicit limit.'));
    }
    for (const m of code.matchAll(/\b(?:getRawBody|rawBody)\s*\(\s*(?:req|request|ctx\.req)\s*(\)|,)/g)) {
      const args = code.slice(m.index, m.index + 300);
      if (m[1] === ',' && /\blimit\s*:/.test(args)) continue;
      out.push(finding(file, code, m.index, 'body-unbounded', 'CWE-770',
        'raw-body read with no limit',
        'raw-body reads the whole request into memory and enforces a size only when a `limit` option is passed; this call passes none.',
        "Pass `{ limit: '1mb' }` (or the largest body the route needs); raw-body then rejects larger bodies with a 413 error."));
    }
  }
  return out;
}

function goBody(file, code, idx, what) {
  return finding(file, code, idx, 'body-unbounded', 'CWE-770',
    `Request body read whole with no size limit: ${what}`,
    `${what} copies the entire request body into memory, and net/http applies no body size limit by default. Nothing in this file wraps the body with http.MaxBytesReader or io.LimitReader, so one client can send a body large enough to exhaust memory.`,
    'Wrap the body before reading it: r.Body = http.MaxBytesReader(w, r.Body, maxBytes) (for gin, the same on c.Request), or read through io.LimitReader and reject bodies at the limit.');
}

// ---------------------------------------------------------------------------
// archive-bomb
// ---------------------------------------------------------------------------

const SIZE_CHECK_RE = /\bfile_size\b|\bcompress_size\b|\bgetSize\s*\(|\bgetCompressedSize\s*\(|\bUncompressedSize(?:64)?\b|\.header\s*\.\s*size\b|\bstatIndex\b|\bstatName\b|\[\s*['"]size['"]\s*\]|\bLimitReader\b|\bLimitedReader\b|\bCopyN\b|\bBoundedInputStream\b|\bmax_length\b|\bdecompressobj\b|\bmax_size\b|[<>]=?\s*[\w.]*(?:MAX|LIMIT|max_|Max[A-Z]|limit)\w*/;

/** Function body (brace languages) or def body (Python/Ruby) around `idx`; whole file if none found. */
function enclosing(code, idx, lang) {
  if (lang === 'py' || lang === 'rb') {
    const before = code.slice(0, idx);
    const defRe = /^([ \t]*)def\s+\w+/gm;
    let last = null, m;
    while ((m = defRe.exec(before))) last = m;
    if (!last) return { start: 0, end: code.length };
    const ind = last[1].length;
    const lines = code.slice(last.index).split('\n');
    let len = lines[0].length + 1;
    for (let i = 1; i < lines.length; i++) {
      const t = lines[i];
      if (t.trim() && t.length - t.trimStart().length <= ind) break;
      len += t.length + 1;
    }
    return { start: last.index, end: Math.min(code.length, last.index + len) };
  }
  const fnRe = lang === 'go' ? /\bfunc\b/g : lang === 'php' ? /\bfunction\b/g : /\b(?:public|private|protected|static|void|function|async)\b[^;{}]{0,200}\)\s*(?:throws[^{]{0,120})?\{|=>\s*\{/g;
  let last = -1, m;
  while ((m = fnRe.exec(code)) && m.index < idx) last = m.index;
  if (last === -1) return { start: 0, end: code.length };
  const open = code.indexOf('{', last);
  if (open === -1 || open > idx) return { start: 0, end: code.length };
  let depth = 0, k = open;
  for (; k < code.length; k++) { if (code[k] === '{') depth++; else if (code[k] === '}') { depth--; if (depth === 0) break; } }
  if (k < idx) return { start: 0, end: code.length };
  return { start: last, end: k + 1 };
}

function scanArchiveBomb(file, code, lang) {
  const out = [];
  const bomb = (idx, what, remediation) => out.push(finding(file, code, idx, 'archive-bomb', 'CWE-400',
    `Archive from the request extracted with no size limit: ${what}`,
    `${what} expands data the client sent, and nothing in this function checks how large the extracted output is. Compressed data and archives can expand by factors of thousands (a decompression bomb, CWE-409), so a small upload can fill memory or disk.`,
    remediation));

  const sinks = {
    py: [
      { re: /\b(?:zlib|gzip|bz2|lzma)\s*\.\s*decompress\s*\(/g, src: /\brequest\s*\.\s*(?:data|body|get_data|files|FILES|stream)\b|\bawait\s+request\s*\.\s*body\s*\(/, what: 'decompress() of request data', fix: 'Use zlib.decompressobj() (or the module\'s decompressor object) and pass max_length to decompress(), rejecting the input once the output passes a maximum.' },
      { re: /\bzipfile\s*\.\s*ZipFile\s*\(|(?<![\w.])ZipFile\s*\(/g, src: /\brequest\s*\.\s*(?:files|FILES|data|get_data|stream)\b|\bUploadFile\b/, need: /\.\s*(?:extractall|extract|read|open)\s*\(/, what: 'zipfile over an upload', fix: 'Before extracting, sum ZipInfo.file_size over infolist() and reject the archive when the total or any entry passes a maximum; read entries through a capped loop.' },
    ],
    java: [
      { re: /\bnew\s+ZipInputStream\s*\(/g, src: /\bgetInputStream\s*\(\s*\)|\bMultipartFile\b|\bPart\b/, need: /\bgetNextEntry\s*\(/, what: 'ZipInputStream over an upload', fix: 'Count the bytes copied from each entry and in total, and stop with an error once either passes a maximum (or check entry.getSize() and enforce it while copying, since the header can lie).' },
    ],
    kt: [
      { re: /\bZipInputStream\s*\(/g, src: /\binputStream\b|\bgetInputStream\s*\(|\bMultipartFile\b|\breceiveMultipart\b/, need: /\bnextEntry\b|\bgetNextEntry\s*\(/, what: 'ZipInputStream over an upload', fix: 'Count the bytes copied from each entry and in total, and stop with an error once either passes a maximum.' },
    ],
    go: [
      { re: /\bzip\s*\.\s*NewReader\s*\(/g, src: /\*http\.Request\b|\bFormFile\s*\(|\bgin\.Context\b|\becho\.Context\b|\.Body\b/, need: /\bio\s*\.\s*(?:Copy|ReadAll)\s*\(|\bioutil\s*\.\s*ReadAll\s*\(/, what: 'archive/zip from a request', fix: 'Check f.UncompressedSize64 against a maximum for each entry and the running total, and copy with io.CopyN or through io.LimitReader so a lying header cannot exceed it.' },
    ],
    php: [
      { re: /->\s*open\s*\(/g, src: /\$_FILES\b|->\s*file\s*\(|getRealPath\s*\(|getPathname\s*\(/, need: /->\s*(?:extractTo|getFromName|getFromIndex|getStream)\s*\(/, gate: /\bZipArchive\b/, what: 'ZipArchive over an upload', fix: 'Loop over the entries with statIndex() and reject the archive when the sum of the size fields, or any one, passes a maximum before calling extractTo().' },
    ],
    js: [
      { re: /\bnew\s+AdmZip\s*\(|(?<![\w$.])AdmZip\s*\(/g, src: /\b(?:req|request)\s*\.\s*(?:file|files|body)\b/, need: /\.\s*(?:extractAllTo|extractEntryTo|getData|readFile|readAsText|getEntries)\s*\(/, what: 'adm-zip over an upload', fix: 'Sum entry.header.size over getEntries() and reject the archive when the total or any entry passes a maximum, before extracting.' },
    ],
    rb: [
      { re: /\bZip\s*::\s*(?:File\s*\.\s*open|InputStream\s*\.\s*(?:open|new))\s*\(/g, src: /\bparams\s*\[[^\]]{1,40}\]\s*(?:\.\s*(?:tempfile|path|read)|\[)|\.tempfile\b/, need: /\.\s*(?:extract|get_input_stream|read)\b/, what: 'rubyzip over an upload', fix: 'Check entry.size against a maximum for each entry and the running total before extracting, and read entries in bounded chunks.' },
    ],
  }[lang] || [];

  for (const s of sinks) {
    if (s.gate && !s.gate.test(code)) continue;
    for (const m of code.matchAll(s.re)) {
      const fn = enclosing(code, m.index, lang);
      const body = code.slice(fn.start, fn.end);
      // Request evidence: in the call's own arguments or in the function.
      if (!s.src.test(body)) continue;
      if (s.need && !s.need.test(body)) continue;
      if (SIZE_CHECK_RE.test(body)) continue;
      bomb(m.index, s.what, s.fix);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

export function scanResourceLimitDisabled(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 400_000) return [];
  if (TEST_PATH_RE.test(file)) return [];
  const lang = SPRING_PROPS_RE.test(file) ? 'props' : langOf(file);
  if (!lang) return [];
  try {
    const seen = new Set();
    const all = [...scanLimitDisabled(file, raw, lang), ...(lang === 'props' ? [] : scanBodyUnbounded(file, raw, lang)), ...(lang === 'props' ? [] : scanArchiveBomb(file, raw, lang))];
    return all.filter((f) => { const k = `${f.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  } catch {
    return [];
  }
}

export const _internals = { SIZE_CHECK_RE, enclosing };
