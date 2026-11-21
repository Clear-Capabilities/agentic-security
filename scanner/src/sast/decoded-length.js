// Lengths, counts and shifts in binary parsers that nothing bounds.
//
// A binary format carries its own sizes: a length prefix, an element count, a
// log2 work factor. The parser reads that number from bytes the sender chose
// and then allocates, loops or slices with it. When no comparison against the
// bytes actually remaining (or against a fixed maximum) sits between the read
// and the use, a short message that claims a large size allocates gigabytes,
// reads past the end of its buffer, or panics the process.
//
// Rules (each is silenced by the comparison its fix adds):
//   go-alloc     a 32/64-bit length decoded from a buffer (`n, err :=
//                b.Uint32()`, `binary.BigEndian.Uint32(...)`, Uvarint) sizes
//                a `make` with no `<`/`>` comparison of it first. CWE-770
//                (CWE-789, allocation from an untrusted size, sits under it).
//   go-wrap      a 32-bit decoded length added to an offset in its own width
//                (`end := 4 + binary.BigEndian.Uint32(p[:4])`) and then used
//                as a slice bound. The sum wraps for lengths near 2^32, so a
//                later `len(p) < int(end)` check passes and the slice panics.
//                CWE-129.
//   cs-count     a count decoded from a byte buffer (`ParseUInt16(buffer, ..)`,
//                `BinaryPrimitives.ReadUInt16BigEndian`, `BitConverter.
//                ToUInt16`) drives a `for` loop that reads that same buffer,
//                with no `if` on the count (or on a value computed from it)
//                before the loop. CWE-125.
//   cs-index     a public method or constructor takes a `byte[]` and reads it
//                at fixed offsets (`value[4]`, `value.AsSpan(2)`, `BitConverter.
//                ToUInt32(value, 8)`) with no `.Length` check of that array
//                anywhere in the method and no try around the reads. A caller
//                handing it a shorter array (a truncated attribute from the
//                wire) throws out of the parser. CWE-20.
//   int-shift    `int x = 1 << n` (Java, C#) where the guard on `n` admits 31:
//                `1 << 31` is negative in a 32-bit int, so a loop bounded by
//                it runs zero times. CWE-190.
//   java-range   a range check that adds two int parameters (`off + len - 1`
//                passed to a check, or `off + len > buf.length`), which wraps
//                negative for large values and passes. CWE-129.
//
// Findings are reported where the size is read (or computed), which is where
// the validation belongs. Test code is skipped.

const TEST_PATH = /(?:^|[\\/])(?:test|tests|spec|__tests__|testdata|fixtures?)[\\/]|_test\.go$|Tests?\.(?:java|cs)$/i;

function finding(file, lines, line, rule, cwe, vuln, description, remediation, parser, family = 'resource-exhaustion') {
  return {
    id: `decoded-length:${rule}:${file}:${line}`,
    file, line, vuln,
    severity: 'medium',
    cwe,
    family,
    stride: 'Denial of Service',
    description, remediation,
    snippet: (lines[line - 1] || '').trim().slice(0, 200),
    parser,
    confidence: 0.5,
  };
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Does any line mention `name` in an ordering comparison or a bounding call? */
function compared(lines, name) {
  const n = esc(name);
  const re = new RegExp(
    `\\b${n}\\b\\s*(?:\\)\\s*)?(?:[<>]=?)(?!>)|(?<![<>-])[<>]=?\\s*(?:\\(?\\s*(?:int|uint|int64|uint64|uint32|long)\\s*\\(\\s*)?${n}\\b|\\b(?:min|max|Min|Max|clamp|check\\w*|validate\\w*|ensure\\w*|require\\w*)\\s*\\([^)\\n]*\\b${n}\\b`);
  return lines.some((l) => re.test(l));
}

// ---------------------------------------------------------------- Go
function goFunctions(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^func\b/.test(lines[i])) continue;
    let j = i + 1;
    while (j < lines.length && !/^\}/.test(lines[j])) j++;
    out.push([i, Math.min(j + 1, lines.length)]);
    i = j;
  }
  return out;
}

const GO_DECODE_METHOD = /^\s*(\w+)\s*,\s*\w+\s*:?=\s*(\w+)\.(Int32|Uint32|Int64|Uint64|Int|Uint|ReadUint32|ReadInt32|ReadUint64|ReadInt64|ReadUvarint|ReadVarint|Uvarint|Varint)\(\s*\)/;
const GO_DECODE_BINARY = /^\s*(\w+)\s*(?:,\s*\w+\s*)?:?=\s*(?:u?int(?:32|64)?\s*\(\s*)?binary\.(?:(?:Big|Little)Endian\.Uint(32|64)\s*\(|Uvarint\s*\(|Varint\s*\()/;
const GO_NOT_DECODER = /^(?:rand|atomic|rng|random|counter|metrics?|stats?)$/i;

function scanGo(file, code, lines) {
  const out = [];
  if (!/\bmake\s*\(|\[[^\]\n]*:/.test(code)) return out;
  for (const [s, e] of goFunctions(lines)) {
    for (let i = s; i < e; i++) {
      const l = lines[i];
      // --- go-wrap: decoded uint32/uint16 added in its own width, used as a slice bound.
      const w = l.match(/^\s*(\w+)\s*:?=\s*(?:\w+|\d+)\s*\+\s*binary\.(?:Big|Little)Endian\.Uint(32|16)\s*\(|^\s*(\w+)\s*:?=\s*binary\.(?:Big|Little)Endian\.Uint(32|16)\s*\([^\n]*\)\s*\+\s*(?:\w+|\d+)\s*$/);
      if (w) {
        const v = w[1] || w[3];
        const after = lines.slice(i + 1, e);
        const slice = new RegExp(`\\[[^\\]\\n]*:\\s*(?:int\\s*\\(\\s*)?${esc(v)}\\b\\s*\\)?\\s*\\]`);
        if (after.some((x) => slice.test(x))) {
          out.push(finding(file, lines, i + 1, 'go-wrap', 'CWE-129',
            'Length arithmetic can wrap before a slice bound',
            `\`${v}\` adds an offset to a ${w[2] || w[4]}-bit length read from the input in ${w[2] || w[4]}-bit arithmetic. A length near the type's maximum wraps to a small number, so a later length check passes and the slice that uses \`${v}\` as its bound panics (or reads the wrong range).`,
            'Convert the decoded length to `int` (or `uint64`) before adding to it, check it against the bytes remaining (`n > len(p)-4`), and only then slice. A structured decoder for the message format avoids the arithmetic altogether.',
            'GO-LENGTH'));
        }
        continue;
      }
      // --- go-alloc: decoded 32/64-bit length sizes an allocation with no comparison first.
      let v = null;
      const dm = l.match(GO_DECODE_METHOD);
      if (dm && !GO_NOT_DECODER.test(dm[2])) v = dm[1];
      const db = !v && l.match(GO_DECODE_BINARY);
      if (db && db[2] !== '16') v = db[1];
      if (!v || v === '_') continue;
      const n = esc(v);
      const allocRe = new RegExp(`\\bmake\\s*\\(\\s*\\[\\][\\w.*\\[\\]]+\\s*,\\s*(?:(?:int|uint|int64|uint64|uint32)\\s*\\(\\s*)?${n}\\b\\s*\\)?\\s*[,)]`);
      for (let k = i + 1; k < Math.min(e, i + 25); k++) {
        if (new RegExp(`^\\s*${n}\\s*(?:,\\s*\\w+\\s*)?:?=(?!=)`).test(lines[k])) break; // reassigned
        if (!allocRe.test(lines[k])) continue;
        if (compared(lines.slice(i + 1, k + 1), v)) break;
        out.push(finding(file, lines, i + 1, 'go-alloc', 'CWE-770',
          'Allocation sized by an unchecked decoded length',
          `\`${v}\` is read from the input and sizes the allocation at line ${k + 1} with no comparison against the bytes remaining or a maximum. A short message that claims a length of gigabytes makes the process allocate it (CWE-789); a negative signed length panics.`,
          `Reject \`${v}\` when it is negative or larger than what is left in the buffer (or a protocol maximum) before allocating.`,
          'GO-LENGTH'));
        break;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- C#
const CS_DECODE = /^\s*(?:ushort|uint|int|short|long|ulong|var|UInt16|UInt32|Int32|Int16)\s+(\w+)\s*=\s*(?:\(\s*\w+\s*\)\s*)?(?:[\w.]+\.)?(?:Parse(?:U?Int(?:16|32|64))|Read(?:U?Int(?:16|32|64))(?:BigEndian|LittleEndian)?|To(?:U?Int(?:16|32|64)))\s*\(\s*(?:new\s+\w+\s*\(\s*)?(\w+)\b/;

function blockEnd(lines, start) {
  let depth = 0; let opened = false;
  for (let k = start; k < lines.length && k < start + 200; k++) {
    for (const c of lines[k]) {
      if (c === '{') { depth++; opened = true; } else if (c === '}') { depth--; if (opened && depth <= 0) return k; }
    }
    if (!opened && k > start && /;\s*$/.test(lines[k])) return k; // single-statement body
  }
  return Math.min(lines.length - 1, start + 1);
}

function scanCSharp(file, code, lines) {
  const out = [];
  if (!/\bfor\s*\(/.test(code)) return out;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(CS_DECODE);
    if (!m) continue;
    const [, v, buf] = m;
    if (/^(?:this|value|s|str|text)$/.test(buf)) continue;
    const n = esc(v);
    const loopRe = new RegExp(`\\bfor\\s*\\([^;]*;\\s*\\w+\\s*<=?\\s*${n}\\s*;`);
    for (let k = i + 1; k < Math.min(lines.length, i + 40); k++) {
      if (/^\s*(?:public|private|protected|internal|static)\b[^=;]*\(/.test(lines[k])) break; // next method
      if (!loopRe.test(lines[k])) continue;
      const end = blockEnd(lines, k);
      const body = lines.slice(k + 1, end + 1).join('\n');
      if (!new RegExp(`\\b${esc(buf)}\\s*(?:\\[|,)`).test(body)) break;
      // A condition on the count, or on a value computed from it, before the loop.
      // Statements, not lines: a computed length is often wrapped over several lines.
      const between = lines.slice(i + 1, k).join('\n').split(/[;{}]/).map((t) => t.replace(/\s+/g, ' '));
      const derived = [v];
      for (const b of between) {
        const a = b.match(/^\s*(?:\w+\s+)?(\w+)\s*[+*-]?=(?!=)/);
        if (a && new RegExp(`\\b(?:${derived.map(esc).join('|')})\\b`).test(b.slice(b.indexOf('=') + 1))) derived.push(a[1]);
      }
      const guardRe = new RegExp(`\\b(?:if|while)\\s*\\([^\\n]*\\b(?:${derived.map(esc).join('|')})\\b|Math\\.M(?:in|ax)\\s*\\([^\\n]*\\b(?:${derived.map(esc).join('|')})\\b`);
      if (between.some((b) => guardRe.test(b))) break;
      out.push(finding(file, lines, i + 1, 'cs-count', 'CWE-125',
        'Loop count read from the input is not checked against the buffer',
        `\`${v}\` is decoded from \`${buf}\` and bounds the loop at line ${k + 1}, which reads \`${buf}\` on every iteration. Nothing compares the count with the length the message declared or the bytes remaining, so a message that claims more entries than it carries reads past its end: stale bytes are parsed as data, or the read leaves the buffer and throws an exception the receive path may not expect.`,
        `Compute the length the count implies (header + \`${v}\` * entry size) and reject the message when it exceeds the declared or remaining length, before the loop.`,
        'CS-LENGTH'));
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------- C#: fixed-offset reads of a byte[] parameter
// A method or constructor that is reachable from outside its class (public, internal, protected) takes a byte array and
// reads it at literal offsets. Protocol attribute parsers look exactly like this, and the array is whatever the sender put
// on the wire. The fix is always the same statement, `if (value.Length < N) ...`, so any `.Length` of that array in the
// method is the off switch; so is a try around the body (the exception is then handled where it is thrown) and a writer
// (the array is an output buffer). A lone `[0]` or `[1]` read is not reported: a parser reading one or two bytes is the
// common case of a length the caller already proved, and the real defects read well past that.
const CS_SIG = /^\s*(?:\[[^\]\n]*\]\s*)*(public|internal|protected)\b(?![^(\n]*\b(?:class|struct|interface|enum|delegate|event|operator)\b)[^;=(\n]*?\b(\w+)\s*\(([^)\n]*)\)/;
const CS_WRITER_NAME = /^(?:Write|To|Serialize|Serialise|Encode|Copy|Fill|Put|Set|Emit)/;
const CS_OUTPUT_PARAM = /^(?:dest|destination|dst|out\w*|output|target|buffer|buf|sink)$/i;
const CS_READ_WIDTH = { Int16: 2, UInt16: 2, Int32: 4, UInt32: 4, Int64: 8, UInt64: 8, Single: 4, Double: 8, Char: 2, Boolean: 1 };

function csBodyRange(lines, i) {
  // The body opens at the first `{` at or after the signature; `: base(...)` / `: this(...)` may sit between. An
  // expression-bodied member (`=>`) or a declaration ending in `;` has no body to judge.
  for (let k = i; k < Math.min(lines.length, i + 6); k++) {
    if (/=>/.test(lines[k]) || (k > i && /^\s*(?:public|private|protected|internal)\b/.test(lines[k]))) return null;
    if (/\{/.test(lines[k])) return [k, blockEnd(lines, k)];
    if (/;\s*$/.test(lines[k])) return null;
  }
  return null;
}

function scanCSharpIndex(file, code, lines) {
  const out = [];
  if (!/\bbyte\s*\[\]/.test(code)) return out;
  for (let i = 0; i < lines.length; i++) {
    const sig = lines[i].match(CS_SIG);
    if (!sig) continue;
    const [, , name, params] = sig;
    if (CS_WRITER_NAME.test(name)) continue;
    const arrays = [...params.matchAll(/\bbyte\s*\[\]\s+(\w+)/g)].map((m) => m[1]).filter((p) => !CS_OUTPUT_PARAM.test(p));
    if (!arrays.length) continue;
    const range = csBodyRange(lines, i);
    if (!range) continue;
    const [open, close] = range;
    const body = lines.slice(open, close + 1);
    const bodyText = body.join('\n');
    if (/\btry\b/.test(bodyText)) { i = close; continue; }
    for (const a of arrays) {
      const n = esc(a);
      // The off switch: any length of this array, or a check call taking it, anywhere in the method.
      if (new RegExp(`\\b${n}\\s*\\??\\.\\s*(?:Length|LongLength|Count\\s*\\()|\\b(?:Check|Validate|Ensure|Require|Guard|Assert)\\w*\\s*\\([^)\\n]*\\b${n}\\b`).test(bodyText)) continue;
      const idxRe = new RegExp(`\\b${n}\\s*\\[\\s*(\\d+)\\s*\\](?!\\s*(?:=[^=]|\\+\\+|--|[-+*/|&^%]=))`, 'g');
      const spanRe = new RegExp(`\\b(?:Read(Int16|UInt16|Int32|UInt32|Int64|UInt64|Single|Double)\\w*\\s*\\(\\s*)?${n}\\s*\\.\\s*AsSpan\\s*\\(\\s*(\\d+)\\s*[,)]`, 'g');
      const convRe = new RegExp(`\\bBitConverter\\s*\\.\\s*To(Int16|UInt16|Int32|UInt32|Int64|UInt64|Single|Double|Char|Boolean)\\s*\\(\\s*${n}\\s*,\\s*0*(\\d+)\\s*\\)`, 'g');
      let need = 0; let first = -1;
      for (let k = open; k <= close; k++) {
        const l = lines[k];
        let m;
        for (m of l.matchAll(idxRe)) { need = Math.max(need, Number(m[1]) + 1); if (first < 0) first = k; }
        for (m of l.matchAll(spanRe)) { need = Math.max(need, Number(m[2]) + (CS_READ_WIDTH[m[1]] || 1)); if (first < 0) first = k; }
        for (m of l.matchAll(convRe)) { need = Math.max(need, Number(m[2]) + (CS_READ_WIDTH[m[1]] || 1)); if (first < 0) first = k; }
      }
      if (first < 0 || need < 3) continue;
      out.push(finding(file, lines, first + 1, 'cs-index', 'CWE-20',
        'Byte array read at fixed offsets with no length check',
        `\`${name}\` reads \`${a}\` at fixed offsets up to byte ${need - 1} and never checks \`${a}.Length\`. The array is whatever the caller received, so a shorter one (a truncated field from the wire) throws an IndexOutOfRangeException or ArgumentOutOfRangeException out of the parser instead of being rejected as malformed; where the parser runs inside a receive loop that is the end of the connection.`,
        `Check \`${a}.Length >= ${need}\` (or the length the field declares) at the top of \`${name}\` and reject or skip the value when it is too short.`,
        'CS-LENGTH', 'input-validation'));
    }
    i = close;
  }
  return out;
}

// ---------------------------------------------------------------- Java / C#: shift overflow
function scanShift(file, code, lines, parser) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*(?:int\s+)?(\w+)\s*=\s*1\s*<<\s*(\w+)\s*;/);
    if (!m || /^\d+$/.test(m[2])) continue;
    const [, x, n] = m;
    // The target must be a 32-bit int: declared on this line or earlier in the window.
    const win = lines.slice(Math.max(0, i - 30), i + 1);
    const intDecl = /^\s*int\s/.test(lines[i]) || win.some((l) => new RegExp(`\\bint\\s[^;=(]*\\b${esc(x)}\\b`).test(l));
    if (!intDecl) continue;
    // A guard that admits 31: `n > 31` rejects only 32 and up.
    const admits31 = win.some((l) => new RegExp(`\\b${esc(n)}\\s*>\\s*31\\b|\\b${esc(n)}\\s*>=\\s*32\\b|\\b${esc(n)}\\s*<=\\s*31\\b|\\b${esc(n)}\\s*<\\s*32\\b`).test(l));
    if (!admits31) continue;
    out.push(finding(file, lines, i + 1, 'int-shift', 'CWE-190',
      'Shift overflows a 32-bit int',
      `\`${x} = 1 << ${n}\` is computed in a 32-bit int while the check on \`${n}\` still admits 31. \`1 << 31\` is negative, so a loop bounded by \`${x}\` runs zero times and the work factor it was meant to impose silently disappears.`,
      `Compute the value in a 64-bit type (\`long ${x} = 1L << ${n}\`) and loop with a long counter, or cap \`${n}\` at 30.`,
      parser));
  }
  return out;
}

// ---------------------------------------------------------------- Java: range check that wraps
function scanJavaRange(file, code, lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const sig = lines[i].match(/\b(?:public|private|protected|static)\b[^=;(]*\(([^)]*)\)\s*(?:throws[^{]*)?\{?\s*$/);
    if (!sig) continue;
    const ints = [...sig[1].matchAll(/\bint\s+(\w+)/g)].map((x) => x[1]);
    if (ints.length < 2) continue;
    const end = blockEnd(lines, i);
    for (let k = i + 1; k <= end; k++) {
      const l = lines[k];
      for (const a of ints) for (const b of ints) {
        if (a === b) continue;
        const sum = `\\b${esc(a)}\\s*\\+\\s*${esc(b)}\\b`;
        const inCheck = new RegExp(`\\bcheck\\w*\\s*\\([^)\\n]*${sum}`).test(l)
          || new RegExp(`${sum}(?:\\s*-\\s*1)?\\s*>=?\\s*[\\w.]+\\.(?:length\\b|capacity\\s*\\(|limit\\s*\\(|size\\s*\\()`).test(l);
        if (!inCheck) continue;
        out.push(finding(file, lines, k + 1, 'java-range', 'CWE-129',
          'Range check can overflow',
          `The range check adds \`${a}\` and \`${b}\` in int arithmetic. For large values the sum wraps negative and the check passes, so an offset and length that do not fit the buffer are accepted. This matters most where the range is then handed to native code or an unchecked memory access.`,
          `Compare without adding: \`${a} < 0 || ${b} < 0 || ${a} > length - ${b}\`.`,
          'JAVA-LENGTH'));
        k = end; break;
      }
    }
    i = end;
  }
  return out;
}

export function scanDecodedLength(file, code) {
  if (typeof code !== 'string' || !code) return [];
  const f = String(file || '');
  if (TEST_PATH.test(f)) return [];
  const lines = code.split('\n');
  if (/\.go$/i.test(f)) return scanGo(f, code, lines);
  if (/\.cs$/i.test(f)) return [...scanCSharp(f, code, lines), ...scanCSharpIndex(f, code, lines), ...scanShift(f, code, lines, 'CS-LENGTH')];
  if (/\.java$/i.test(f)) return [...scanShift(f, code, lines, 'JAVA-LENGTH'), ...scanJavaRange(f, code, lines)];
  return [];
}
